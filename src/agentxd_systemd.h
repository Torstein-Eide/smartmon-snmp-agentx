// agentxd_systemd.h — sd_notify helpers
#pragma once

// Send STATUS= string built from current g_cache state (drives, scan time, last poll).
void agentxd_sd_notify_status();
