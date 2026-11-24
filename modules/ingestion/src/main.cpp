// Ingestion Service - entry point for sensor data.
//
// Discovers the Storage service through the registry (never hardcoded) and
// forwards readings to it. Exposes request counters and a latency histogram
// for Prometheus, so the DDoS experiment can observe load and p95 latency
// here as well as at the target.
//
// It also applies PROACTIVE per-identity rate limiting (the DoS guide's
// suggested mitigation). Each sensor identity gets its own token bucket, so a
// flood on one identity is shed at the service with HTTP 429 - before it
// reaches storage and before the slower SIEM/firewall-drop response. Keying
// the limit on the sensor's hierarchical NAME rather than its source IP is
// deliberate: a node container hosting 50 sensors presents one IP but 50
// identities, so a per-IP limit cannot tell that node from an attacker (the
// scalability finding), whereas per-identity limiting lets the 50 legitimate
// sensors through while still catching a flood that reuses one identity.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

#include <httplib.h>

#include <ssle/ssle.hpp>

using ssle::json;

namespace {

std::atomic<uint64_t> g_received{0};
std::atomic<uint64_t> g_forwarded{0};
std::atomic<uint64_t> g_failed{0};
std::atomic<uint64_t> g_ratelimited{0};

// ---- Per-identity token-bucket rate limiter --------------------------------
// A real sensor posts about once every few seconds; the defaults (5 req/s
// sustained, burst of 10) leave ample headroom for a healthy sensor while
// shedding a flood of hundreds per second on a single identity. Both are
// env-tunable (RATE_LIMIT_RPS, RATE_LIMIT_BURST).
class RateLimiter {
public:
    RateLimiter(double rps, double burst) : rps_(rps), burst_(burst) {}

    bool allow(const std::string& key) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(mutex_);
        Bucket& b = buckets_[key];
        if (b.last.time_since_epoch().count() == 0) {
            b.tokens = burst_;  // first sighting starts full
        } else {
            double elapsed = std::chrono::duration<double>(now - b.last).count();
            b.tokens = std::min(burst_, b.tokens + elapsed * rps_);
        }
        b.last = now;
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            return true;
        }
        return false;
    }

    // Drop buckets untouched for a while, so a flood of distinct identities
    // cannot grow the map without bound.
    void evict(std::chrono::seconds older_than) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = buckets_.begin(); it != buckets_.end();) {
            if (now - it->second.last > older_than)
                it = buckets_.erase(it);
            else
                ++it;
        }
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(mutex_);
        return buckets_.size();
    }

private:
    struct Bucket {
        double tokens = 0;
        std::chrono::steady_clock::time_point last{};
    };
    double rps_, burst_;
    std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
};

// Prometheus histogram of /ingest latency, so p95 can be computed with
// histogram_quantile() during the DDoS experiment.
constexpr std::array<double, 8> kBuckets = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0};
std::array<std::atomic<uint64_t>, kBuckets.size()> g_bucket{};
std::atomic<uint64_t> g_lat_count{0};
std::mutex g_sum_mutex;
double g_lat_sum = 0.0;

void observe(double seconds) {
    for (size_t i = 0; i < kBuckets.size(); ++i)
        if (seconds <= kBuckets[i]) g_bucket[i]++;
    g_lat_count++;
    std::lock_guard<std::mutex> lock(g_sum_mutex);
    g_lat_sum += seconds;
}

}  // namespace

int main() {
    ssle::Identity id = ssle::Identity::from_env("ingestion", 5001);
    ssle::RegistryClient registry(id.registry_url);

    static RateLimiter limiter(ssle::env_double("RATE_LIMIT_RPS", 5.0),
                               ssle::env_double("RATE_LIMIT_BURST", 10.0));

    httplib::Server server;

    server.Post("/ingest", [&registry](const httplib::Request& req, httplib::Response& res) {
        auto start = std::chrono::steady_clock::now();
        g_received++;

        json body = ssle::parse_json(req.body);
        // Rate-limit per sensor identity; fall back to source IP for a request
        // that carries no identity (itself anomalous, and what a crude flood
        // looks like).
        std::string key;
        if (!body.is_discarded() && body.contains("sensor") && body["sensor"].is_string())
            key = "id:" + body["sensor"].get<std::string>();
        else
            key = "ip:" + req.remote_addr;
        if (!limiter.allow(key)) {
            g_ratelimited++;
            res.status = 429;  // Too Many Requests
            res.set_content(R"({"error":"rate limit exceeded"})", "application/json");
            observe(std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
            return;
        }

        // One cache per thread: avoids asking the registry on every request
        // while still rediscovering quickly when storage moves.
        thread_local ssle::CachedDiscovery storage(registry, "storage");

        auto url = storage.get();
        if (!url) {
            g_failed++;
            res.status = 503;
            res.set_content(R"({"error":"no storage service available"})", "application/json");
        } else {
            auto r = ssle::http_post(*url, "/store", body.is_discarded() ? json::object() : body);
            if (r.ok()) {
                g_forwarded++;
                res.status = 201;
                res.set_content(R"({"ingested":true})", "application/json");
            } else {
                g_failed++;
                storage.invalidate();  // storage may have moved or died
                res.status = r.status == 0 ? 502 : r.status;
                res.set_content(R"({"error":"forward to storage failed"})", "application/json");
            }
        }
        observe(std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count());
    });

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server.Get("/metrics", [](const httplib::Request&, httplib::Response& res) {
        std::ostringstream out;
        out << ssle::metric_header("ssle_ingestion_received_total", "Readings received.",
                                   "counter")
            << "ssle_ingestion_received_total " << g_received.load() << "\n"
            << ssle::metric_header("ssle_ingestion_forwarded_total",
                                   "Readings forwarded to storage.", "counter")
            << "ssle_ingestion_forwarded_total " << g_forwarded.load() << "\n"
            << ssle::metric_header("ssle_ingestion_failed_total",
                                   "Readings that could not be forwarded.", "counter")
            << "ssle_ingestion_failed_total " << g_failed.load() << "\n"
            << ssle::metric_header("ssle_ingestion_ratelimited_total",
                                   "Readings rejected by per-identity rate limiting (HTTP 429).",
                                   "counter")
            << "ssle_ingestion_ratelimited_total " << g_ratelimited.load() << "\n"
            << ssle::metric_header("ssle_ingestion_rate_buckets",
                                   "Active per-identity rate-limit buckets.", "gauge")
            << "ssle_ingestion_rate_buckets " << limiter.size() << "\n";

        out << ssle::metric_header("ssle_ingestion_latency_seconds",
                                   "Latency of /ingest requests.", "histogram");
        for (size_t i = 0; i < kBuckets.size(); ++i)
            out << "ssle_ingestion_latency_seconds_bucket{le=\"" << kBuckets[i] << "\"} "
                << g_bucket[i].load() << "\n";
        uint64_t count = g_lat_count.load();
        double sum;
        {
            std::lock_guard<std::mutex> lock(g_sum_mutex);
            sum = g_lat_sum;
        }
        out << "ssle_ingestion_latency_seconds_bucket{le=\"+Inf\"} " << count << "\n"
            << "ssle_ingestion_latency_seconds_sum " << sum << "\n"
            << "ssle_ingestion_latency_seconds_count " << count << "\n";
        res.set_content(out.str(), "text/plain");
    });

    // Evict idle rate-limit buckets so a flood of distinct identities cannot
    // grow the map without bound.
    std::thread([] {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            limiter.evict(std::chrono::seconds(300));
        }
    }).detach();

    ssle::enable_access_log(server, id);
    ssle::start_heartbeat(id);
    ssle::log("ingestion listening on :" + std::to_string(id.port));

    // A large worker pool: cpp-httplib dedicates a thread to each live
    // (keep-alive) connection, so the default ~11 cannot serve 100+ sensors.
    server.new_task_queue = [] { return new httplib::ThreadPool(256); };

    server.listen("0.0.0.0", id.port);
    return 0;
}
