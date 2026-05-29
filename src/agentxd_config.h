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

    // Path to SQLite DB for persisting table-change timestamps across restarts.
    // Empty (default) disables persistence; timestamps still work within a run.
    std::string state_db_path;

    // When true, traps fire on every refresh regardless of prior state.
    // Intended for CI/integration tests; disables state-based throttling.
    bool test_mode { false };

    // Seconds between re-sending a persistent sensor alarm (0 = never resend).
    uint32_t sensor_resend_interval { 0 };

    // Units of hysteresis applied when clearing a sensor alarm.
    // For high alarms: value must drop below (threshold - hysteresis) to clear.
    // For low alarms:  value must rise above (threshold + hysteresis) to clear.
    int32_t sensor_hysteresis { 0 };
};

// Verbosity level: 0=off, 1=-v (flow), 2=-vv (per-sensor/iterator detail)
extern int g_verbosity;

// Mirror of AgentxConfig::poll_failure_threshold, set at startup so MIB
// handlers and datasrc can read it without carrying the full config struct.
extern uint32_t g_poll_failure_threshold;

// When true, traps fire unconditionally on every refresh (no state tracking).
// Set from AgentxConfig::test_mode for use in datasrc without carrying config.
extern bool g_test_mode;

// Mirror of AgentxConfig::sensor_resend_interval.
extern uint32_t g_sensor_resend_interval;

// Mirror of AgentxConfig::sensor_hysteresis.
extern int32_t g_sensor_hysteresis;

// Parse /etc/smartmontools/snmp-agentxd.conf (or path given on command line).
// Returns false and logs an error if the file cannot be read or a required
// option is missing.
bool agentxd_config_load(const char *path, AgentxConfig &out);
