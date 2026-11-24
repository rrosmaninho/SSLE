// Service Registry - the directory every other service discovers through.
//
// Beyond the Guide 1 example it adds heartbeat-based health checking with a
// TTL (stale instances are hidden from discovery and eventually evicted),
// load-balanced discovery across healthy instances of the same kind, a
// Prometheus /metrics endpoint, and /unregister (used as the C2 incident
// response to cut a compromised service out of the architecture).
//
// State is in-memory on purpose; losing it on restart is one of the honest
// scalability bottlenecks discussed in the report (single registry).
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#include <httplib.h>

#include <ssle/ssle.hpp>

using ssle::json;

namespace {

constexpr int kTtlSeconds = 30;  // heartbeat older than this => instance is down

// How long a dead instance is remembered. This is deliberately long: an
// instance that is forgotten also disappears from service discovery, and a
// target that is no longer scraped cannot raise `up == 0`. Forgetting it
// quickly would silently resolve the alert for a service that is still down.
// Permanent removal is an explicit action (/unregister), which is also how
// the C2 incident response evicts a compromised service.
constexpr int kForgetSeconds = 3600;

struct Entry {
    std::string kind;
    std::string url;
    json labels;
    double last_seen = 0;
    double registered_at = 0;
};

double now_seconds() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

std::mutex g_mutex;
std::map<std::string, Entry> g_registry;                 // name -> entry
std::map<std::string, std::atomic<uint64_t>> g_rr;       // kind -> round-robin cursor

bool healthy(const Entry& e, double now) { return (now - e.last_seen) <= kTtlSeconds; }

}  // namespace

int main() {
    httplib::Server server;

    server.Post("/register", [](const httplib::Request& req, httplib::Response& res) {
        json data = ssle::parse_json(req.body);
        if (data.is_discarded() || !data.contains("name") || !data.contains("url")) {
            res.status = 400;
            res.set_content(R"({"error":"Missing name or url"})", "application/json");
            return;
        }
        const std::string name = data["name"];
        double now = now_seconds();
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            Entry& e = g_registry[name];
            double first = e.registered_at ? e.registered_at : now;
            e.kind = data.value("kind", "unknown");
            e.url = data["url"];
            e.labels = data.value("labels", json::object());
            e.last_seen = now;
            e.registered_at = first;
        }
        res.set_content(json{{"message", name + " registered"}}.dump(), "application/json");
    });

    server.Post("/heartbeat", [](const httplib::Request& req, httplib::Response& res) {
        json data = ssle::parse_json(req.body);
        const std::string name = data.is_discarded() ? "" : data.value("name", "");
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_registry.find(name);
        if (it != g_registry.end()) {
            it->second.last_seen = now_seconds();
            res.set_content(R"({"message":"ok"})", "application/json");
        } else {
            res.status = 404;  // tells the caller to re-register
            res.set_content(R"({"error":"unknown, please re-register"})", "application/json");
        }
    });

    auto unregister = [](const httplib::Request& req, httplib::Response& res) {
        json data = ssle::parse_json(req.body);
        const std::string name = data.is_discarded() ? "" : data.value("name", "");
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_registry.erase(name)) {
            res.set_content(json{{"message", name + " unregistered"}}.dump(), "application/json");
        } else {
            res.status = 404;
            res.set_content(R"({"error":"Not found"})", "application/json");
        }
    };
    server.Delete("/unregister", unregister);
    server.Post("/unregister", unregister);

    server.Get(R"(/discover/(.+))", [](const httplib::Request& req, httplib::Response& res) {
        const std::string kind = req.matches[1];
        double now = now_seconds();
        std::vector<Entry> candidates;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            for (const auto& [name, e] : g_registry)
                if (e.kind == kind && healthy(e, now)) candidates.push_back(e);
        }
        if (candidates.empty()) {
            res.status = 404;
            res.set_content(json{{"error", "no healthy instance of " + kind}}.dump(),
                            "application/json");
            return;
        }
        uint64_t i = g_rr[kind].fetch_add(1) % candidates.size();
        const Entry& e = candidates[i];
        res.set_content(json{{"kind", e.kind}, {"url", e.url}, {"labels", e.labels}}.dump(),
                        "application/json");
    });

    server.Get("/services", [](const httplib::Request&, httplib::Response& res) {
        double now = now_seconds();
        json out = json::object();
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& [name, e] : g_registry) {
            out[name] = {{"kind", e.kind},         {"url", e.url},
                         {"labels", e.labels},     {"healthy", healthy(e, now)},
                         {"age", now - e.last_seen}};
        }
        res.set_content(out.dump(), "application/json");
    });

    server.Get(R"(/services/(.+))", [](const httplib::Request& req, httplib::Response& res) {
        const std::string name = req.matches[1];
        double now = now_seconds();
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_registry.find(name);
        if (it == g_registry.end()) {
            res.status = 404;
            res.set_content(R"({"error":"Not found"})", "application/json");
            return;
        }
        const Entry& e = it->second;
        res.set_content(json{{"kind", e.kind},
                             {"url", e.url},
                             {"labels", e.labels},
                             {"healthy", healthy(e, now)},
                             {"age", now - e.last_seen}}
                            .dump(),
                        "application/json");
    });

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    // Prometheus HTTP service discovery. Prometheus polls this instead of
    // keeping a static target list, so scaling the architecture (more
    // sensors, more nodes) needs no monitoring config change. Location
    // labels travel with each target, which is what makes per-location
    // monitoring possible.
    //
    // Stale instances are deliberately still advertised. Discovery must not
    // filter them out: a target that disappears from the list simply stops
    // being scraped, so `up == 0` never fires and a dead service vanishes
    // silently instead of raising an alert. They are labelled
    // registry_state="stale" so queries can tell "down" from "healthy".
    server.Get("/sd", [](const httplib::Request&, httplib::Response& res) {
        double now = now_seconds();
        // Several instances can share one metrics endpoint: a sensor node
        // runs many logical sensors behind a single /metrics port. Scraping
        // it once per sensor would multiply load for identical data, so
        // targets are deduplicated by host:port and the shared endpoint is
        // labelled with its node rather than one arbitrary sensor name.
        struct Target {
            std::string kind, service, region, dc, rack, node;
            int instances = 0;
            bool any_healthy = false;
        };
        std::map<std::string, Target> targets;  // host:port -> labels
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            for (const auto& [name, e] : g_registry) {
                std::string hostport = e.url;  // Prometheus wants host:port
                auto pos = hostport.find("://");
                if (pos != std::string::npos) hostport = hostport.substr(pos + 3);

                auto [it, inserted] = targets.try_emplace(hostport);
                Target& t = it->second;
                if (inserted) {
                    t.kind = e.kind;
                    t.service = name;
                    t.region = e.labels.value("region", "");
                    t.dc = e.labels.value("dc", "");
                    t.rack = e.labels.value("rack", "");
                    t.node = e.labels.value("node", "");
                }
                t.instances++;
                if (healthy(e, now)) t.any_healthy = true;
            }
        }
        json out = json::array();
        for (const auto& [hostport, t] : targets) {
            // A shared endpoint identifies the node, not one instance.
            std::string service = t.instances > 1
                                      ? t.kind + "s." + t.node + "." + t.rack + "." + t.dc +
                                            "." + t.region
                                      : t.service;
            out.push_back({{"targets", json::array({hostport})},
                           {"labels",
                            {{"kind", t.kind},
                             {"service", service},
                             {"region", t.region},
                             {"dc", t.dc},
                             {"rack", t.rack},
                             {"node", t.node},
                             {"instances", std::to_string(t.instances)},
                             {"registry_state", t.any_healthy ? "healthy" : "stale"}}}});
        }
        res.set_content(out.dump(), "application/json");
    });

    server.Get("/metrics", [](const httplib::Request&, httplib::Response& res) {
        double now = now_seconds();
        // (kind, state, region, dc, rack) -> count
        std::map<std::tuple<std::string, std::string, std::string, std::string, std::string>, int>
            counts;
        size_t total;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            total = g_registry.size();
            for (const auto& [name, e] : g_registry) {
                counts[{e.kind, healthy(e, now) ? "healthy" : "stale",
                        e.labels.value("region", ""), e.labels.value("dc", ""),
                        e.labels.value("rack", "")}]++;
            }
        }
        std::ostringstream out;
        out << ssle::metric_header("ssle_registry_services",
                                   "Registered instances by kind and health.", "gauge");
        for (const auto& [key, n] : counts) {
            const auto& [kind, state, region, dc, rack] = key;
            out << "ssle_registry_services{kind=\"" << ssle::escape_label(kind) << "\",state=\""
                << state << "\",region=\"" << ssle::escape_label(region) << "\",dc=\""
                << ssle::escape_label(dc) << "\",rack=\"" << ssle::escape_label(rack) << "\"} " << n
                << "\n";
        }
        out << ssle::metric_header("ssle_registry_total", "Total registered instances.", "gauge");
        out << "ssle_registry_total " << total << "\n";
        res.set_content(out.str(), "text/plain");
    });

    // Reaper: forget instances that have been gone for a long time, so the
    // registry does not grow without bound as containers are recreated.
    std::thread([] {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(kTtlSeconds));
            double now = now_seconds();
            std::lock_guard<std::mutex> lock(g_mutex);
            for (auto it = g_registry.begin(); it != g_registry.end();) {
                if (now - it->second.last_seen > kForgetSeconds)
                    it = g_registry.erase(it);
                else
                    ++it;
            }
        }
    }).detach();

    ssle::Identity id = ssle::Identity::from_env("registry", 5050);
    ssle::enable_access_log(server, id);
    ssle::log("registry listening on :" + std::to_string(id.port));
    // A large worker pool: cpp-httplib dedicates a thread to each live

    // (keep-alive) connection, so the default ~11 cannot serve 100+ sensors.

    server.new_task_queue = [] { return new httplib::ThreadPool(256); };

    server.listen("0.0.0.0", id.port);
    return 0;
}
