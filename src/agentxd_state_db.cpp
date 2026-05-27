// agentxd_state_db.cpp — SQLite persistence for table-level change timestamps

#include "agentxd_state_db.h"
#include "agentxd_cache.h"

#include <sqlite3.h>
#include <syslog.h>

static sqlite3 *g_db = nullptr;

bool state_db_open(const std::string &path) {
    if (path.empty()) return true;

    if (sqlite3_open(path.c_str(), &g_db) != SQLITE_OK) {
        syslog(LOG_WARNING, "state_db: cannot open '%s': %s",
               path.c_str(), sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = nullptr;
        return false;
    }

    const char *sql =
        "CREATE TABLE IF NOT EXISTS table_state ("
        "  table_id    INTEGER PRIMARY KEY,"
        "  hash        INTEGER NOT NULL,"
        "  last_change INTEGER NOT NULL"
        ");";
    char *errmsg = nullptr;
    if (sqlite3_exec(g_db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        syslog(LOG_WARNING, "state_db: CREATE TABLE failed: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(g_db);
        g_db = nullptr;
        return false;
    }
    return true;
}

void state_db_load() {
    if (!g_db) return;

    const char *sql = "SELECT table_id, hash, last_change FROM table_state;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int      id = sqlite3_column_int(stmt, 0);
        uint64_t h  = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
        time_t   ts = static_cast<time_t>(sqlite3_column_int64(stmt, 2));

        if (id < 0 || id >= TABLE_COUNT) continue;
        g_cache.table_hashes[id] = h;

        switch (id) {
        case TABLE_DEVICE:        g_cache.ts_device_table       = ts; break;
        case TABLE_NVME_CTRL:     g_cache.ts_nvme_controller    = ts; break;
        case TABLE_NVME_NS:       g_cache.ts_nvme_namespace      = ts; break;
        case TABLE_NVME_HEALTH:   g_cache.ts_nvme_health         = ts; break;
        case TABLE_NVME_SELFTEST: g_cache.ts_nvme_selftest       = ts; break;
        case TABLE_NVME_ERRLOG:   g_cache.ts_nvme_error_log      = ts; break;
        case TABLE_NVME_CAP:      g_cache.ts_nvme_capability     = ts; break;
        case TABLE_NVME_PS:       g_cache.ts_nvme_power_state    = ts; break;
        case TABLE_NVME_LBA:      g_cache.ts_nvme_lba_format     = ts; break;
        case TABLE_SATA_INFO:     g_cache.ts_sata_info           = ts; break;
        case TABLE_SATA_HEALTH:   g_cache.ts_sata_health         = ts; break;
        case TABLE_SATA_ATTR:     g_cache.ts_sata_attr           = ts; break;
        case TABLE_SATA_ERRLOG:   g_cache.ts_sata_error_log      = ts; break;
        case TABLE_SATA_ERRCMD:   g_cache.ts_sata_error_cmd      = ts; break;
        case TABLE_SATA_SELFTEST: g_cache.ts_sata_selftest       = ts; break;
        case TABLE_SATA_ERC:      g_cache.ts_sata_erc            = ts; break;
        case TABLE_SATA_PHY:      g_cache.ts_sata_phy_event      = ts; break;
        case TABLE_SATA_SELTEST:  g_cache.ts_sata_selective_test = ts; break;
        case TABLE_SATA_PENDING:  g_cache.ts_sata_pending_defects= ts; break;
        case TABLE_SATA_LOGDIR:   g_cache.ts_sata_log_dir        = ts; break;
        case TABLE_SATA_DEVSTAT:  g_cache.ts_sata_dev_stat       = ts; break;
        case TABLE_SAS_INFO:      g_cache.ts_sas_info            = ts; break;
        case TABLE_SAS_HEALTH:    g_cache.ts_sas_health          = ts; break;
        case TABLE_SAS_ERRCNT:    g_cache.ts_sas_error_counter   = ts; break;
        case TABLE_SAS_SELFTEST:  g_cache.ts_sas_selftest        = ts; break;
        case TABLE_SAS_BGSCAN:    g_cache.ts_sas_bgscan          = ts; break;
        case TABLE_SENSOR:        g_cache.ts_sensor              = ts; break;
        }
    }
    sqlite3_finalize(stmt);
}

void state_db_update(int table_id, uint64_t hash, time_t ts) {
    if (!g_db) return;

    const char *sql =
        "INSERT OR REPLACE INTO table_state (table_id, hash, last_change)"
        " VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int(stmt, 1, table_id);
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(hash));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(ts));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_close() {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = nullptr;
    }
}
