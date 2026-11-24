#include <ssle/ssle.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#include <httplib.h>

namespace ssle {

// ---- Environment -----------------------------------------------------------
std::string env(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

int env_int(const char* key, int fallback) {
    try {
        return std::stoi(env(key, std::to_string(fallback)));
    } catch (...) {
        return fallback;
    }
}

double env_double(const char* key, double fallback) {
    try {
        return std::stod(env(key, std::to_string(fallback)));
    } catch (...) {
        return fallback;
    }
}

// ---- Identity --------------------------------------------------------------
Identity Identity::from_env(const std::string& default_kind, int default_port) {
    Identity id;
    id.kind = env("SERVICE_KIND", default_kind);
    id.name = env("SERVICE_NAME", id.kind + "-01.unknown");
    id.registry_url = env("REGISTRY_URL", "http://registry.incus:5050");
    id.region = env("REGION");
    id.dc = env("DC");
    id.rack = env("RACK");
    id.node = env("NODE");
    id.port = env_int("SERVICE_PORT", default_port);
    if (id.port == 0) id.port = default_port;
    id.heartbeat_interval = env_int("HEARTBEAT_INTERVAL", 10);
    return id;
}

json Identity::labels() const {
    return {{"region", region}, {"dc", dc}, {"rack", rack}, {"node", node}};
}

std::string local_ip() {
    // Connecting a UDP socket sends nothing; it only selects the route,
    // which tells us the source address used on the lab network.
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return "127.0.0.1";
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(1);
    ::inet_pton(AF_INET, "10.255.255.1", &dst.sin_addr);
    std::string result = "127.0.0.1";
    if (::connect(fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) == 0) {
        sockaddr_in src{};
        socklen_t len = sizeof(src);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&src), &len) == 0) {
            char buf[INET_ADDRSTRLEN] = {};
            if (::inet_ntop(AF_INET, &src.sin_addr, buf, sizeof(buf))) result = buf;
        }
    }
    ::close(fd);
    return result;
}

// ---- HTTP client helpers ---------------------------------------------------
namespace {

httplib::Client make_client(const std::string& base_url, int timeout_s) {
    httplib::Client cli(base_url);
    cli.set_connection_timeout(timeout_s, 0);
    cli.set_read_timeout(timeout_s, 0);
    cli.set_write_timeout(timeout_s, 0);
    return cli;
}

HttpResult to_result(const httplib::Result& r) {
    HttpResult out;
    if (r) {
        out.status = r->status;
        out.body = r->body;
    }
    return out;
}

}  // namespace

HttpResult http_get(const std::string& base_url, const std::string& path, int timeout_s) {
    auto cli = make_client(base_url, timeout_s);
    return to_result(cli.Get(path));
}

HttpResult http_post(const std::string& base_url, const std::string& path, const json& body,
                     int timeout_s) {
    auto cli = make_client(base_url, timeout_s);
    return to_result(cli.Post(path, body.dump(), "application/json"));
}

json parse_json(const std::string& text) {
    return json::parse(text, nullptr, /*allow_exceptions=*/false);
}

// ---- Registry client -------------------------------------------------------
RegistryClient::RegistryClient(std::string registry_url) : url_(std::move(registry_url)) {}

bool RegistryClient::register_instance(const std::string& name, const std::string& kind,
                                       const std::string& url, const json& labels) const {
    json payload = {{"name", name}, {"kind", kind}, {"url", url}, {"labels", labels}};
    return http_post(url_, "/register", payload).ok();
}

int RegistryClient::heartbeat(const std::string& name) const {
    return http_post(url_, "/heartbeat", json{{"name", name}}).status;
}

std::optional<std::string> RegistryClient::discover(const std::string& kind) const {
    auto r = http_get(url_, "/discover/" + kind);
    if (!r.ok()) return std::nullopt;
    auto j = parse_json(r.body);
    if (j.is_discarded() || !j.contains("url") || !j["url"].is_string()) return std::nullopt;
    return j["url"].get<std::string>();
}

std::optional<std::string> RegistryClient::discover_retry(const std::string& kind, int attempts,
                                                          int delay_s) const {
    for (int i = 0; i < attempts; ++i) {
        if (auto u = discover(kind)) return u;
        std::this_thread::sleep_for(std::chrono::seconds(delay_s));
    }
    return std::nullopt;
}

CachedDiscovery::CachedDiscovery(const RegistryClient& registry, std::string kind,
                                 std::chrono::seconds ttl)
    : registry_(registry), kind_(std::move(kind)), ttl_(ttl) {}

std::optional<std::string> CachedDiscovery::get() {
    // Not shared between threads; each caller owns its own instance.
    auto now = std::chrono::steady_clock::now();
    if (!valid_ || now - fetched_ > ttl_) {
        url_ = registry_.discover(kind_);
        fetched_ = now;
        valid_ = url_.has_value();
    }
    return url_;
}

void CachedDiscovery::invalidate() { valid_ = false; }

void start_heartbeat(const Identity& id) {
    std::thread([id] {
        RegistryClient registry(id.registry_url);
        const std::string url = "http://" + local_ip() + ":" + std::to_string(id.port);
        bool registered = false;
        while (true) {
            if (!registered) {
                registered = registry.register_instance(id.name, id.kind, url, id.labels());
                if (registered) log("registered as " + id.name + " at " + url);
            } else if (registry.heartbeat(id.name) != 200) {
                registered = false;  // re-register on the next tick
                continue;
            }
            std::this_thread::sleep_for(
                std::chrono::seconds(registered ? id.heartbeat_interval : 2));
        }
    }).detach();
}

// ---- Logging ---------------------------------------------------------------
void log(const std::string& message) {
    static std::mutex m;
    std::lock_guard<std::mutex> lock(m);
    std::cout << message << std::endl;
}

void enable_access_log(httplib::Server& server, const Identity& id) {
    const std::string path = env("ACCESS_LOG", "/var/log/ssle/" + id.kind + "-access.log");
    auto out = std::make_shared<std::ofstream>(path, std::ios::app);
    if (!*out) {
        log("WARN: cannot open access log " + path);
        return;
    }
    auto m = std::make_shared<std::mutex>();
    server.set_logger([out, m](const httplib::Request& req, const httplib::Response& res) {
        // Apache Common Log Format:
        // 10.0.0.1 - - [21/Nov/2026:05:20:01 +0000] "POST /ingest HTTP/1.1" 201 17
        char ts[64];
        std::time_t now = std::time(nullptr);
        std::tm tm{};
        ::gmtime_r(&now, &tm);
        std::strftime(ts, sizeof(ts), "%d/%b/%Y:%H:%M:%S +0000", &tm);
        std::lock_guard<std::mutex> lock(*m);
        *out << req.remote_addr << " - - [" << ts << "] \"" << req.method << ' ' << req.path
             << ' ' << req.version << "\" " << res.status << ' ' << res.body.size() << '\n';
        out->flush();
    });
}

// ---- Prometheus ------------------------------------------------------------
std::string metric_header(const std::string& name, const std::string& help,
                          const std::string& type) {
    return "# HELP " + name + " " + help + "\n# TYPE " + name + " " + type + "\n";
}

std::string escape_label(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        if (c == '\\' || c == '"') out += '\\';
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        out += c;
    }
    return out;
}

}  // namespace ssle
