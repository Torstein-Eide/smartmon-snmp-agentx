// agentxd_config.h — configuration for smartmon-snmp-agentxd

#pragma once

#include <cstdint>
#include <string>

struct AgentxConfig {
    // Required: directory where smartd writes --jsonstate files
    std::string state_dir;

    // Path to AgentX master socket
    std::string agentx_socket { "/var/agentx/master" };

    // net-snmp cache timeout in seconds (also staleness threshold base)
    unsigned cache_timeout { 300 };

    // Run in foreground instead of daemonising (set by -f flag)
    bool foreground { false };

    // Consecutive non-ok poll results required before emitting the
    // smartmonDevicePollFailed trap (default 1 = fire on first failure)
    uint32_t poll_failure_threshold { 1 };
};

// Verbosity level: 0=off, 1=-v (flow), 2=-vv (per-sensor/iterator detail)
extern int g_verbosity;

// Mirror of AgentxConfig::poll_failure_threshold, set at startup so MIB
// handlers and datasrc can read it without carrying the full config struct.
extern uint32_t g_poll_failure_threshold;

// Parse /etc/smartmontools/snmp-agentxd.conf (or path given on command line).
// Returns false and logs an error if the file cannot be read or a required
// option is missing.
bool agentxd_config_load(const char *path, AgentxConfig &out);
