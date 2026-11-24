// Storage Service - persists sensor readings in SQLite and serves queries.
//
// SQLite is deliberately simple; its single-writer design is one of the
// documented scalability bottlenecks discussed in the evaluation.
#include <atomic>
#include <mutex>
#include <sstream>
#include <string>

#include <httplib.h>
#include <sqlite3.h>

#include <ssle/ssle.hpp>

using ssle::json;

namespace {

sqlite3* g_db = nullptr;
std::mutex g_db_mutex;  // SQLite has a single writer; serialise access

std::atomic<uint64_t> g_stored{0};
std::atomic<uint64_t> g_errors{0};

bool open_db(const std::string& path) {
    if (sqlite3_open(path.c_str(), &g_db) != SQLITE_OK) return false;
    char* err = nullptr;
    const char* schema =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS readings ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " sensor TEXT, value REAL, unit TEXT,"
        " region TEXT, dc TEXT, rack TEXT, node TEXT,"
        " ts REAL);"
        "CREATE INDEX IF NOT EXISTS idx_readings_ts ON readings(ts);";
    if (sqlite3_exec(g_db, schema, nullptr, nullptr, &err) != SQLITE_OK) {
        ssle::log(std::string("schema error: ") + (err ? err : "?"));
        sqlite3_free(err);
        return false;
    }
    return true;
}

// Single-column aggregate helper.
double scalar(const char* sql, bool* is_null = nullptr) {
    sqlite3_stmt* st = nullptr;
    double v = 0;
    if (is_null) *is_null = true;
    if (sqlite3_prepare_v2(g_db, sql, -1, &st, nullptr) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
                v = sqlite3_column_double(st, 0);
                if (is_null) *is_null = false;
            }
        }
    }
    sqlite3_finalize(st);
    return v;
}

}  // namespace

int main() {
    ssle::Identity id = ssle::Identity::from_env("storage", 5002);
    const std::string db_path = ssle::env("DB_PATH", "/var/lib/ssle/storage.db");
    if (!open_db(db_path)) {
        ssle::log("FATAL: cannot open database " + db_path);
        return 1;
    }

    httplib::Server server;

    server.Post("/store", [](const httplib::Request& req, httplib::Response& res) {
        json d = ssle::parse_json(req.body);
        if (d.is_discarded() || !d.contains("value")) {
            g_errors++;
            res.status = 400;
            res.set_content(R"({"error":"invalid reading"})", "application/json");
            return;
        }
        json labels = d.value("labels", json::object());
        // Parameter binding, so a crafted sensor name cannot inject SQL.
        const char* sql =
            "INSERT INTO readings (sensor,value,unit,region,dc,rack,node,ts)"
            " VALUES (?,?,?,?,?,?,?,?)";
        std::lock_guard<std::mutex> lock(g_db_mutex);
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(g_db, sql, -1, &st, nullptr) != SQLITE_OK) {
            g_errors++;
            res.status = 500;
            res.set_content(R"({"error":"prepare failed"})", "application/json");
            return;
        }
        auto text = [&](int i, const std::string& s) {
            sqlite3_bind_text(st, i, s.c_str(), -1, SQLITE_TRANSIENT);
        };
        text(1, d.value("sensor", ""));
        sqlite3_bind_double(st, 2, d["value"].is_number() ? d["value"].get<double>() : 0.0);
        text(3, d.value("unit", "C"));
        text(4, labels.value("region", ""));
        text(5, labels.value("dc", ""));
        text(6, labels.value("rack", ""));
        text(7, labels.value("node", ""));
        sqlite3_bind_double(st, 8, d.value("ts", 0.0));
        bool ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
        if (ok) {
            g_stored++;
            res.status = 201;
            res.set_content(R"({"stored":true})", "application/json");
        } else {
            g_errors++;
            res.status = 500;
            res.set_content(R"({"error":"insert failed"})", "application/json");
        }
    });

    server.Get("/readings", [](const httplib::Request& req, httplib::Response& res) {
        int limit = 100;
        if (req.has_param("limit")) {
            try {
                limit = std::max(1, std::min(10000, std::stoi(req.get_param_value("limit"))));
            } catch (...) {
            }
        }
        std::lock_guard<std::mutex> lock(g_db_mutex);
        sqlite3_stmt* st = nullptr;
        sqlite3_prepare_v2(g_db,
                           "SELECT sensor,value,unit,region,dc,rack,node,ts FROM readings"
                           " ORDER BY id DESC LIMIT ?",
                           -1, &st, nullptr);
        sqlite3_bind_int(st, 1, limit);
        json out = json::array();
        auto col = [&](int i) {
            const unsigned char* t = sqlite3_column_text(st, i);
            return t ? std::string(reinterpret_cast<const char*>(t)) : std::string();
        };
        while (sqlite3_step(st) == SQLITE_ROW) {
            out.push_back({{"sensor", col(0)},
                           {"value", sqlite3_column_double(st, 1)},
                           {"unit", col(2)},
                           {"region", col(3)},
                           {"dc", col(4)},
                           {"rack", col(5)},
                           {"node", col(6)},
                           {"ts", sqlite3_column_double(st, 7)}});
        }
        sqlite3_finalize(st);
        res.set_content(out.dump(), "application/json");
    });

    server.Get("/stats", [](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(g_db_mutex);
        bool empty = false;
        double count = scalar("SELECT COUNT(*) FROM readings");
        double mn = scalar("SELECT MIN(value) FROM readings", &empty);
        double mx = scalar("SELECT MAX(value) FROM readings");
        double avg = scalar("SELECT AVG(value) FROM readings");
        json out{{"count", static_cast<long long>(count)}};
        if (empty) {
            out["min"] = out["max"] = out["avg"] = nullptr;
        } else {
            out["min"] = mn;
            out["max"] = mx;
            out["avg"] = avg;
        }
        res.set_content(out.dump(), "application/json");
    });

    server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server.Get("/metrics", [](const httplib::Request&, httplib::Response& res) {
        long long rows;
        {
            std::lock_guard<std::mutex> lock(g_db_mutex);
            rows = static_cast<long long>(scalar("SELECT COUNT(*) FROM readings"));
        }
        std::ostringstream out;
        out << ssle::metric_header("ssle_storage_readings_total", "Rows stored since boot.",
                                   "counter")
            << "ssle_storage_readings_total " << g_stored.load() << "\n"
            << ssle::metric_header("ssle_storage_errors_total", "Failed store operations.",
                                   "counter")
            << "ssle_storage_errors_total " << g_errors.load() << "\n"
            << ssle::metric_header("ssle_storage_rows", "Current row count in the database.",
                                   "gauge")
            << "ssle_storage_rows " << rows << "\n";
        res.set_content(out.str(), "text/plain");
    });

    ssle::enable_access_log(server, id);
    ssle::start_heartbeat(id);
    ssle::log("storage listening on :" + std::to_string(id.port) + " db=" + db_path);
    // A large worker pool: cpp-httplib dedicates a thread to each live

    // (keep-alive) connection, so the default ~11 cannot serve 100+ sensors.

    server.new_task_queue = [] { return new httplib::ThreadPool(256); };

    server.listen("0.0.0.0", id.port);
    return 0;
}
