// agentxd_loop.cpp — AgentX subagent init, MIB registration, select loop

#include "agentxd_loop.h"
#include "agentxd_config.h"
#include "agentxd_cache.h"
#include "agentxd_datasrc.h"
#include "agentxd_systemd.h"

#include "snmp_common_mib.h"
#include "snmp_nvme_mib.h"
#include "snmp_sata_mib.h"
#include "snmp_sas_mib.h"
#include "snmp_sensor_mib.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdint>
#include <syslog.h>
#include <unistd.h>
#include <sys/select.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <systemd/sd-daemon.h>

// ---------------------------------------------------------------------------
// AgentX init
// ---------------------------------------------------------------------------

bool agentxd_loop_init(const AgentxConfig &cfg) {
    // Tell net-snmp we are a subagent, not a master agent
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_ROLE, 1 /* subagent */);

    // Set AgentX socket path
    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                          NETSNMP_DS_AGENT_X_SOCKET,
                          cfg.agentx_socket.c_str());

    // Suppress net-snmp's own logging unless explicitly requested for
    // AgentX registration/debugging runs.
    const char *netsnmp_log = getenv("AGENTXD_NETSNMP_LOG");
    if (netsnmp_log && strcmp(netsnmp_log, "0") != 0) {
        snmp_enable_stderrlog();
        const char *tokens = getenv("AGENTXD_NETSNMP_DEBUG");
        if (tokens && *tokens) {
            snmp_set_do_debugging(1);
            debug_register_tokens(tokens);
        }
    } else {
        snmp_disable_log();
    }

    if (init_agent("smartmon-snmp-agentxd") != 0) {
        syslog(LOG_ERR, "init_agent failed — cannot connect to snmpd AgentX socket %s",
               cfg.agentx_socket.c_str());
        return false;
    }

    // Register all MIB table handlers
    register_common_mib();
    register_nvme_mib();
    register_sata_mib();
    register_sas_mib();
    register_sensor_mib();

    init_snmp("smartmon-snmp-agentxd");

    syslog(LOG_INFO, "AgentX subagent registered on %s",
           cfg.agentx_socket.c_str());
    return true;
}

// ---------------------------------------------------------------------------
// Select loop
// ---------------------------------------------------------------------------

bool agentxd_loop_run(volatile sig_atomic_t *exit_flag,
                      volatile sig_atomic_t *reload_flag,
                      const AgentxConfig &cfg) {
    time_t last_staleness = time(nullptr);

    // Watchdog: send WATCHDOG=1 at half the configured interval
    uint64_t wdog_usec = 0;
    bool use_watchdog = (sd_watchdog_enabled(0, &wdog_usec) > 0);
    struct timespec last_wdog = {0, 0};
    if (use_watchdog)
        clock_gettime(CLOCK_MONOTONIC, &last_wdog);

    while (!*exit_flag) {
        if (*reload_flag) {
            *reload_flag = 0;
            syslog(LOG_INFO, "SIGHUP — rescanning %s", cfg.state_dir.c_str());
            sd_notify(0, "RELOADING=1");
            agentxd_datasrc_shutdown();
            g_cache.clear();   // discard stale device rows from before the rescan
            if (!agentxd_datasrc_init(cfg.state_dir))
                syslog(LOG_WARNING, "Rescan failed — serving empty cache until next SIGHUP");
            agentxd_sd_notify_status();
        }

        fd_set fdset;
        FD_ZERO(&fdset);
        int maxfd = -1;

        // Add inotify fd if available
        int ifd = agentxd_datasrc_fd();
        if (ifd >= 0) {
            FD_SET(ifd, &fdset);
            maxfd = std::max(maxfd, ifd);
        }

        // Let net-snmp add its own fds (AgentX socket, etc.)
        struct timeval timeout;
        timeout.tv_sec  = 1;   // check signals at least every second
        timeout.tv_usec = 0;
        int block = 0;
        snmp_select_info(&maxfd, &fdset, &timeout, &block);

        int n = select(maxfd + 1, &fdset, nullptr, nullptr,
                       block ? nullptr : &timeout);
        if (n < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "select: %s — exiting", strerror(errno));
            return false;
        }

        if (n > 0) {
            // Handle inotify events (new/updated JSON state files)
            if (ifd >= 0 && FD_ISSET(ifd, &fdset)) {
                FD_CLR(ifd, &fdset);
                agentxd_datasrc_handle_events();
                agentxd_sd_notify_status();
            }
            // Let net-snmp process AgentX traffic (GET, GETNEXT, keepalive)
            snmp_read(&fdset);
        }

        // Drive net-snmp timers (retransmits, keepalive ping to master)
        snmp_timeout();
        run_alarms();
        netsnmp_check_outstanding_agent_requests();

        // Periodic staleness check (every ~60 s)
        time_t now = time(nullptr);
        if (now - last_staleness >= 60) {
            agentxd_datasrc_check_staleness(cfg.cache_timeout);
            last_staleness = now;
        }

        // Watchdog keepalive
        if (use_watchdog) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t elapsed = (uint64_t)(ts.tv_sec - last_wdog.tv_sec) * 1000000ULL
                             + (uint64_t)(ts.tv_nsec - last_wdog.tv_nsec) / 1000ULL;
            if (elapsed >= wdog_usec / 2) {
                sd_notify(0, "WATCHDOG=1");
                last_wdog = ts;
            }
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

void agentxd_loop_shutdown() {
    snmp_shutdown("smartmon-snmp-agentxd");
}
