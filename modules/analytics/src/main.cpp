// Analytics Service - periodically pulls aggregates from Storage and exposes
// them, plus a simple anomaly flag, for Prometheus.
//
// The anomaly flag (a reading outside a plausible temperature band) is the
// kind of "general anomaly" signal the spec asks to be able to generate and
// later correlate for root-cause detection.
#include <chrono>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>

#include <httplib.h>

#include <ssle/ssle.hpp>

using ssle::json;

namespace {

// Plausible band for a temperature sensor; outside this is anomalous.
constexpr double kLow = -20.0;
constexpr double kHigh = 60.0;

struct State {
    long long count = 0;
    std::optional<double> min, max, avg;
    int anomalies = 0;
    double last_update = 0;
    bool storage_reachable = false;
};

std::mutex g_mutex;
State g_state;

double now_seconds() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

void poll_loop(const ssle::RegistryClient& registry) {
    auto storage = registry.discover_retry("storage");
    while (true) {
        bool ok = false;
        if (storage) {
            auto s = ssle::http_get(*storage, "/stats");
            auto r = ssle::http_get(*storage, "/readings?limit=50");
            if (s.ok() && r.ok()) {
                json js = ssle::parse_json(s.body);
                json jr = ssle::parse_json(r.body);
                if (!js.is_discarded() && !jr.is_discarded()) {
                    int anomalies = 0;
                    for (const auto& item : jr)
                        if (item.contains("value") && item["value"].is_number()) {
                            double v = item["value"];
                            if (v < kLow || v > kHigh) anomalies++;
                        }
                    std::lock_guard<std::mutex> lock(g_mutex);
                    g_state.count = js.value("count", 0LL);
                    auto num = [&](const char* k) -> std::optional<double> {
                        if (js.contains(k) && js[k].is_number()) return js[k].get<double>();
                        return std::nullopt;
                    };
                    g_state.min = num("min");
                    g_state.max = num("max");
                    g_state.avg = num("avg");
                    g_state.anomalies = anomalies;
                    g_state.last_update = now_seconds();
                    g_state.storage_reachable = true;
                    ok = true;
                }
            }
        }
        if (!ok) {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_state.storage_reachable = false;
            }
            if (auto fresh = registry.discover("storage")) storage = fresh;  // it may have moved
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

}  // namespace

int main() {
    ssle::Identity id = ssle::Identity::from_env("analytics", 5003);
    ssle::RegistryClient registry(id.registry_url);

    httplib::Server server;

    server.Get("/report", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_mutex);
        json out{{"count", g_state.count},
                 {"anomalies", g_state.anomalies},
                 {"last_update", g_state.last_update},
                 {"storage_reachable", g_state.storage_reachable}};
        auto put = [&](const char* k, const std::optional<double>& v) {
            if (v) out[k] = *v; else out[k] = nullptr;
        };
        put("min", g_state.min);
        put("max", g_state.max);
        put("avg", g_state.avg);
        res.set_content(out.dump(), "application/json");
    });

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server.Get("/metrics", [](const httplib::Request&, httplib::Response& res) {
        State s;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            s = g_state;
        }
        std::ostringstream out;
        auto gauge = [&](const char* name, const char* help, double value) {
            out << ssle::metric_header(name, help, "gauge") << name << " " << value << "\n";
        };
        gauge("ssle_analytics_readings", "Total readings seen by analytics.",
              static_cast<double>(s.count));
        if (s.min) gauge("ssle_analytics_temp_min", "Minimum temperature observed.", *s.min);
        if (s.max) gauge("ssle_analytics_temp_max", "Maximum temperature observed.", *s.max);
        if (s.avg) gauge("ssle_analytics_temp_avg", "Average temperature observed.", *s.avg);
        gauge("ssle_analytics_anomalies", "Readings outside the plausible band.", s.anomalies);
        gauge("ssle_analytics_storage_up", "Whether storage answered the last poll.",
              s.storage_reachable ? 1 : 0);
        res.set_content(out.str(), "text/plain");
    });

    ssle::enable_access_log(server, id);
    ssle::start_heartbeat(id);
    std::thread([&registry] { poll_loop(registry); }).detach();
    ssle::log("analytics listening on :" + std::to_string(id.port));
    // A large worker pool: cpp-httplib dedicates a thread to each live

    // (keep-alive) connection, so the default ~11 cannot serve 100+ sensors.

    server.new_task_queue = [] { return new httplib::ThreadPool(256); };

    server.listen("0.0.0.0", id.port);
    return 0;
}
