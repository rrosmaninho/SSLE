// Shared helpers for SSLE services: identity and hierarchical naming,
// registry client (register / heartbeat / discover), HTTP helpers,
// access logging and Prometheus text formatting.
//
// Every service is identified by a hierarchical name that encodes its
// logical and physical location, e.g.
//
//     ingestion-01.node2.rack1.dc-aveiro.pt-centro.pt
//
// so an incident source can be located quickly. The parts are also kept as
// separate labels (region, dc, rack, node) for per-location monitoring.
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace httplib {
class Server;
}

namespace ssle {

using json = nlohmann::json;

// ---- Environment -----------------------------------------------------------
std::string env(const char* key, const std::string& fallback = "");
int env_int(const char* key, int fallback);
double env_double(const char* key, double fallback);

// ---- Identity --------------------------------------------------------------
struct Identity {
    std::string kind;          // e.g. "ingestion"
    std::string name;          // full hierarchical id
    std::string registry_url;  // bootstrap address, the only one known up front
    std::string region, dc, rack, node;
    int port = 0;
    int heartbeat_interval = 10;

    static Identity from_env(const std::string& default_kind, int default_port);
    json labels() const;
};

// Primary IPv4 address of this container on the lab network.
std::string local_ip();

// ---- HTTP client helpers ---------------------------------------------------
struct HttpResult {
    int status = 0;  // 0 = connection error / timeout
    std::string body;
    bool ok() const { return status >= 200 && status < 300; }
};

HttpResult http_get(const std::string& base_url, const std::string& path, int timeout_s = 5);
HttpResult http_post(const std::string& base_url, const std::string& path, const json& body,
                     int timeout_s = 5);

// Parse JSON without throwing; returns a discarded value on error.
json parse_json(const std::string& text);

// ---- Registry client -------------------------------------------------------
class RegistryClient {
public:
    explicit RegistryClient(std::string registry_url);

    bool register_instance(const std::string& name, const std::string& kind,
                           const std::string& url, const json& labels) const;
    // Returns the HTTP status (404 = registry does not know us, 0 = unreachable).
    int heartbeat(const std::string& name) const;
    std::optional<std::string> discover(const std::string& kind) const;
    // Blocks until the kind appears, so start-up order does not matter.
    std::optional<std::string> discover_retry(const std::string& kind, int attempts = 30,
                                              int delay_s = 2) const;

private:
    std::string url_;
};

// Discovery with a short cache, so a busy service does not ask the registry
// on every request. Call invalidate() after a failed call to the target.
class CachedDiscovery {
public:
    CachedDiscovery(const RegistryClient& registry, std::string kind,
                    std::chrono::seconds ttl = std::chrono::seconds(5));
    std::optional<std::string> get();
    void invalidate();

private:
    const RegistryClient& registry_;
    std::string kind_;
    std::chrono::seconds ttl_;
    std::optional<std::string> url_;
    std::chrono::steady_clock::time_point fetched_{};
    bool valid_ = false;
};

// Register this instance, then heartbeat from a background thread for the
// life of the process. Re-registers if the registry forgot us (e.g. it was
// restarted and lost its in-memory table).
void start_heartbeat(const Identity& id);

// ---- Logging ---------------------------------------------------------------
// One line to stdout (journald), flushed immediately.
void log(const std::string& message);

// Write every request to ACCESS_LOG (default /var/log/ssle/<kind>-access.log)
// in Apache Common Log Format, so the SIEM can parse it later.
void enable_access_log(httplib::Server& server, const Identity& id);

// ---- Prometheus ------------------------------------------------------------
std::string metric_header(const std::string& name, const std::string& help,
                          const std::string& type);
std::string escape_label(const std::string& value);

}  // namespace ssle
