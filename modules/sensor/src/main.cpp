// Temperature Sensor(s).
//
// One container represents a physical NODE that hosts several logical
// sensors (SENSOR_COUNT of them), each a thread with its own hierarchical id:
//
//     sensor-<i>.<node>.<rack>.<dc>.<region>
//
// This lets the evaluation scale to 10/50/100 sensors by changing one number
// per node instead of launching one container per sensor (the dir storage
// driver would copy the whole rootfs each time).
//
// Each logical sensor registers under its own id, discovers Ingestion
// through the registry, posts a reading every SENSOR_PERIOD seconds and
// heartbeats. The node exposes /metrics on SERVICE_PORT with per-sensor
// counters. A fraction of readings can be made out-of-band (ANOMALY_RATE)
// to exercise the anomaly / correlation path.
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <httplib.h>
#include <memory>

#include <ssle/ssle.hpp>

using ssle::json;


namespace {

struct SensorStats {
    std::atomic<uint64_t> sent{0};
    std::atomic<uint64_t> failed{0};
    std::atomic<double> last{0.0};
};

std::mutex g_stats_mutex;
std::map<std::string, std::unique_ptr<SensorStats>> g_stats;  // name -> counters

SensorStats& stats_for(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_stats_mutex);
    auto& p = g_stats[name];
    if (!p) p = std::make_unique<SensorStats>();
    return *p;
}

double now_seconds() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

void run_sensor(int index, const ssle::Identity& node, double period, double anomaly_rate) {
    const std::string pad = index < 10 ? "0" : "";
    const std::string name = "sensor-" + pad + std::to_string(index) + "." + node.node + "." +
                             node.rack + "." + node.dc + "." + node.region;
    SensorStats& st = stats_for(name);

    ssle::RegistryClient registry(node.registry_url);
    const std::string url = "http://" + ssle::local_ip() + ":" + std::to_string(node.port);

    std::mt19937 rng(std::random_device{}() ^ (index * 2654435761u));
    std::uniform_real_distribution<double> jitter(-1.5, 1.5);
    std::uniform_real_distribution<double> unit(0.0, 1.0);
    const double base = 20.0 + std::uniform_real_distribution<double>(-3, 3)(rng);

    while (!registry.register_instance(name, "sensor", url, node.labels()))
        std::this_thread::sleep_for(std::chrono::seconds(2));

    auto ingestion = registry.discover_retry("ingestion");
    double last_hb = now_seconds();

    while (true) {
        double value;
        if (anomaly_rate > 0 && unit(rng) < anomaly_rate) {
            value = unit(rng) < 0.5 ? -50.0 : 120.0;  // clearly out of band
        } else {
            value = base + jitter(rng);
        }
        value = std::round(value * 100.0) / 100.0;

        json reading{{"sensor", name},
                     {"value", value},
                     {"unit", "C"},
                     {"ts", now_seconds()},
                     {"labels", node.labels()}};

        bool ok = false;
        if (ingestion) ok = ssle::http_post(*ingestion, "/ingest", reading).ok();
        if (!ok) {
            if (auto fresh = registry.discover("ingestion")) ingestion = fresh;
            st.failed++;
        } else {
            st.sent++;
        }
        st.last.store(value);

        if (now_seconds() - last_hb >= node.heartbeat_interval) {
            if (registry.heartbeat(name) == 404)  // registry forgot us
                registry.register_instance(name, "sensor", url, node.labels());
            last_hb = now_seconds();
        }
        std::this_thread::sleep_for(std::chrono::duration<double>(period));
    }
}

}  // namespace

int main() {
    ssle::Identity node = ssle::Identity::from_env("sensor", 9101);
    if (node.node.empty()) node.node = "node1";
    if (node.rack.empty()) node.rack = "rack1";
    if (node.dc.empty()) node.dc = "dc-aveiro";
    if (node.region.empty()) node.region = "pt-centro.pt";

    const int count = ssle::env_int("SENSOR_COUNT", 5);
    const double period = ssle::env_double("SENSOR_PERIOD", 5.0);
    const double anomaly_rate = ssle::env_double("ANOMALY_RATE", 0.0);

    ssle::log("starting " + std::to_string(count) + " sensors on " + node.node + "." + node.rack +
              "." + node.dc + "." + node.region);

    for (int i = 1; i <= count; ++i) {
        std::thread([i, node, period, anomaly_rate] { run_sensor(i, node, period, anomaly_rate); })
            .detach();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));  // stagger start-up
    }

    httplib::Server server;

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server.Get("/metrics", [](const httplib::Request&, httplib::Response& res) {
        std::vector<std::pair<std::string, std::array<double, 3>>> snap;
        {
            std::lock_guard<std::mutex> lock(g_stats_mutex);
            for (const auto& [name, s] : g_stats)
                snap.push_back({name,
                                {static_cast<double>(s->sent.load()),
                                 static_cast<double>(s->failed.load()), s->last.load()}});
        }
        std::ostringstream out;
        struct Metric {
            const char* name;
            const char* help;
            const char* type;
            int index;
        };
        for (const Metric& m :
             {Metric{"ssle_sensor_sent_total", "Readings accepted by ingestion.", "counter", 0},
              Metric{"ssle_sensor_failed_total", "Readings that failed to send.", "counter", 1},
              Metric{"ssle_sensor_last_value", "Last temperature reading (C).", "gauge", 2}}) {
            out << ssle::metric_header(m.name, m.help, m.type);
            for (const auto& [name, vals] : snap)
                out << m.name << "{sensor=\"" << ssle::escape_label(name) << "\"} "
                    << vals[m.index] << "\n";
        }
        out << ssle::metric_header("ssle_sensor_count", "Logical sensors on this node.", "gauge")
            << "ssle_sensor_count " << snap.size() << "\n";
        res.set_content(out.str(), "text/plain");
    });

    ssle::log("sensor node metrics on :" + std::to_string(node.port));
    server.new_task_queue = [] { return new httplib::ThreadPool(64); };

    server.listen("0.0.0.0", node.port);
    return 0;
}
