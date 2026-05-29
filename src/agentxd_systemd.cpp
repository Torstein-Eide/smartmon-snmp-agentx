// agentxd_systemd.cpp — sd_notify status string builder

#include "agentxd_systemd.h"
#include "agentxd_cache.h"
#include "version.h"

#include <systemd/sd-daemon.h>
#include <cstdio>
#include <ctime>

void agentxd_sd_notify_status() {
    char poll_buf[16] = "never";
    if (g_cache.last_scan_time != 0) {
        struct tm tm;
        localtime_r(&g_cache.last_scan_time, &tm);
        strftime(poll_buf, sizeof(poll_buf), "%H:%M:%S", &tm);
    }

    char msg[256];
    snprintf(msg, sizeof(msg),
             "STATUS=v" AGENTXD_VERSION " connected, drives=%zu, scan=%ums, last poll=%s",
             g_cache.devices.size(),
             g_cache.last_scan_ms,
             poll_buf);
    sd_notify(0, msg);
}
