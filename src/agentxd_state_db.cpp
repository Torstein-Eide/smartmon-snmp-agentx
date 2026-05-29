// agentxd_state_db.cpp — SQLite persistence for table-level change timestamps

#include "agentxd_state_db.h"
#include "agentxd_cache.h"

#include <sqlite3.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

static sqlite3 *g_db = nullptr;
static std::string g_db_path;

static std::string parent_dir(const std::string &path) {
    std::size_t slash = path.rfind('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

static void log_open_failure_details(const std::string &path) {
    struct stat st{};
    std::string dir = parent_dir(path);

    if (stat(dir.c_str(), &st) != 0) {
        syslog(LOG_WARNING, "state_db: directory '%s' is not accessible: %m",
               dir.c_str());
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        syslog(LOG_WARNING, "state_db: parent path '%s' is not a directory",
               dir.c_str());
        return;
    }
    if (access(dir.c_str(), W_OK) != 0) {
        syslog(LOG_WARNING,
               "state_db: directory '%s' is not writable by this service: %m",
               dir.c_str());
    }
    if (access(path.c_str(), F_OK) == 0 && access(path.c_str(), W_OK) != 0) {
        syslog(LOG_WARNING,
               "state_db: database file '%s' is not writable by this service: %m",
               path.c_str());
    }
}

bool state_db_open(const std::string &path) {
    if (path.empty()) {
        syslog(LOG_INFO, "state_db: disabled");
        return true;
    }

    bool existed = (access(path.c_str(), F_OK) == 0);

    if (sqlite3_open_v2(path.c_str(), &g_db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        nullptr) != SQLITE_OK) {
        syslog(LOG_WARNING, "state_db: cannot open '%s': %s",
               path.c_str(), sqlite3_errmsg(g_db));
        log_open_failure_details(path);
        sqlite3_close(g_db);
        g_db = nullptr;
        return false;
    }
    g_db_path = path;

    const char *sql =
        "CREATE TABLE IF NOT EXISTS table_state ("
        "  table_id    INTEGER PRIMARY KEY,"
        "  hash        INTEGER NOT NULL,"
        "  last_change INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS sata_by_dev_state ("
        "  dev_id      INTEGER NOT NULL,"
        "  table_id    INTEGER NOT NULL,"
        "  hash        INTEGER NOT NULL,"
        "  last_change INTEGER NOT NULL,"
        "  PRIMARY KEY (dev_id, table_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS sata_devstat_page_state ("
        "  dev_id      INTEGER NOT NULL,"
        "  page_num    INTEGER NOT NULL,"
        "  hash        INTEGER NOT NULL,"
        "  last_change INTEGER NOT NULL,"
        "  PRIMARY KEY (dev_id, page_num)"
        ");"
        "CREATE TABLE IF NOT EXISTS sensor_alarm_state ("
        "  dev_id      INTEGER NOT NULL,"
        "  sensor_idx  INTEGER NOT NULL,"
        "  alarm_state INTEGER NOT NULL,"
        "  last_sent   INTEGER NOT NULL,"
        "  PRIMARY KEY (dev_id, sensor_idx)"
        ");"
        "CREATE TABLE IF NOT EXISTS sata_attr_alarm ("
        "  dev_id   INTEGER NOT NULL,"
        "  attr_id  INTEGER NOT NULL,"
        "  PRIMARY KEY (dev_id, attr_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS sas_uncorrected_baseline ("
        "  dev_id      INTEGER NOT NULL,"
        "  direction   INTEGER NOT NULL,"
        "  uncorrected INTEGER NOT NULL,"
        "  PRIMARY KEY (dev_id, direction)"
        ");"
        "CREATE TABLE IF NOT EXISTS sata_selftest_progress ("
        "  dev_id               INTEGER PRIMARY KEY,"
        "  start_ns             INTEGER NOT NULL,"
        "  last_remaining       INTEGER NOT NULL,"
        "  polling_min          INTEGER NOT NULL,"
        "  estimated_completion INTEGER NOT NULL"
        ");";
    char *errmsg = nullptr;
    if (sqlite3_exec(g_db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        syslog(LOG_WARNING, "state_db: CREATE TABLE failed: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(g_db);
        g_db = nullptr;
        g_db_path.clear();
        return false;
    }
    syslog(LOG_INFO, "state_db: %s '%s'",
           existed ? "opened" : "created", g_db_path.c_str());
    return true;
}

void state_db_load() {
    if (!g_db) return;

    const char *sql = "SELECT table_id, hash, last_change FROM table_state;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        syslog(LOG_WARNING, "state_db: load failed: %s", sqlite3_errmsg(g_db));
        return;
    }

    unsigned loaded = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int      id = sqlite3_column_int(stmt, 0);
        uint64_t h  = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
        time_t   ts = static_cast<time_t>(sqlite3_column_int64(stmt, 2));

        if (id < 0 || id >= TABLE_COUNT) continue;
        g_cache.table_hashes[id] = h;

        switch (id) {
        case TABLE_DEVICE:        g_cache.ts_device_table        = {ts, 0}; break;
        case TABLE_NVME_CTRL:     g_cache.ts_nvme_controller     = {ts, 0}; break;
        case TABLE_NVME_NS:       g_cache.ts_nvme_namespace       = {ts, 0}; break;
        case TABLE_NVME_HEALTH:   g_cache.ts_nvme_health          = {ts, 0}; break;
        case TABLE_NVME_SELFTEST: g_cache.ts_nvme_selftest        = {ts, 0}; break;
        case TABLE_NVME_ERRLOG:   g_cache.ts_nvme_error_log       = {ts, 0}; break;
        case TABLE_NVME_CAP:      g_cache.ts_nvme_capability      = {ts, 0}; break;
        case TABLE_NVME_PS:       g_cache.ts_nvme_power_state     = {ts, 0}; break;
        case TABLE_NVME_LBA:      g_cache.ts_nvme_lba_format      = {ts, 0}; break;
        case TABLE_SATA_INFO:     g_cache.ts_sata_info            = {ts, 0}; break;
        case TABLE_SATA_HEALTH:   g_cache.ts_sata_health          = {ts, 0}; break;
        case TABLE_SATA_ATTR:     g_cache.ts_sata_attr            = {ts, 0}; break;
        case TABLE_SATA_ERRLOG:   g_cache.ts_sata_error_log       = {ts, 0}; break;
        case TABLE_SATA_ERRCMD:   g_cache.ts_sata_error_cmd       = {ts, 0}; break;
        case TABLE_SATA_SELFTEST: g_cache.ts_sata_selftest        = {ts, 0}; break;
        case TABLE_SATA_ERC:      g_cache.ts_sata_erc             = {ts, 0}; break;
        case TABLE_SATA_PHY:      g_cache.ts_sata_phy_event       = {ts, 0}; break;
        case TABLE_SATA_SELTEST:  g_cache.ts_sata_selective_test  = {ts, 0}; break;
        case TABLE_SATA_PENDING:  g_cache.ts_sata_pending_defects = {ts, 0}; break;
        case TABLE_SATA_LOGDIR:   g_cache.ts_sata_log_dir         = {ts, 0}; break;
        case TABLE_SATA_DEVSTAT:  g_cache.ts_sata_dev_stat        = {ts, 0}; break;
        case TABLE_SAS_INFO:      g_cache.ts_sas_info             = {ts, 0}; break;
        case TABLE_SAS_HEALTH:    g_cache.ts_sas_health           = {ts, 0}; break;
        case TABLE_SAS_ERRCNT:    g_cache.ts_sas_error_counter    = {ts, 0}; break;
        case TABLE_SAS_SELFTEST:  g_cache.ts_sas_selftest         = {ts, 0}; break;
        case TABLE_SAS_BGSCAN:    g_cache.ts_sas_bgscan           = {ts, 0}; break;
        case TABLE_SENSOR:        g_cache.ts_sensor               = {ts, 0}; break;
        }
        ++loaded;
    }
    sqlite3_finalize(stmt);
    syslog(LOG_INFO, "state_db: loaded %u table timestamp(s)", loaded);

    // Load per-(device, tableId) ByDevice timestamps.
    const char *sql2 =
        "SELECT dev_id, table_id, hash, last_change FROM sata_by_dev_state;";
    if (sqlite3_prepare_v2(g_db, sql2, -1, &stmt, nullptr) == SQLITE_OK) {
        unsigned n = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint32_t dev = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            uint32_t tid = static_cast<uint32_t>(sqlite3_column_int64(stmt, 1));
            uint64_t h   = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
            time_t   ts  = static_cast<time_t>(sqlite3_column_int64(stmt, 3));
            uint64_t key = ((uint64_t)dev << 32) | tid;
            g_cache.hash_sata_by_dev[key] = h;
            g_cache.ts_sata_by_dev[key]   = {ts, 0};
            ++n;
        }
        sqlite3_finalize(stmt);
        syslog(LOG_INFO, "state_db: loaded %u ByDevice timestamp(s)", n);
    }

    // Load per-page devstat BySubindex timestamps.
    const char *sql3 =
        "SELECT dev_id, page_num, hash, last_change FROM sata_devstat_page_state;";
    if (sqlite3_prepare_v2(g_db, sql3, -1, &stmt, nullptr) == SQLITE_OK) {
        unsigned n = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint32_t dev  = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            uint32_t page = static_cast<uint32_t>(sqlite3_column_int64(stmt, 1));
            uint64_t h    = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
            time_t   ts   = static_cast<time_t>(sqlite3_column_int64(stmt, 3));
            uint64_t key  = ((uint64_t)dev << 32) | page;
            g_cache.hash_sata_devstat_by_page[key] = h;
            g_cache.ts_sata_devstat_by_page[key]   = {ts, 0};
            ++n;
        }
        sqlite3_finalize(stmt);
        syslog(LOG_INFO, "state_db: loaded %u devstat page timestamp(s)", n);
    }

    // Load sensor alarm state.
    const char *sql4 =
        "SELECT dev_id, sensor_idx, alarm_state, last_sent FROM sensor_alarm_state;";
    if (sqlite3_prepare_v2(g_db, sql4, -1, &stmt, nullptr) == SQLITE_OK) {
        unsigned n = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint32_t dev    = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            uint32_t sidx   = static_cast<uint32_t>(sqlite3_column_int64(stmt, 1));
            int      astate = sqlite3_column_int(stmt, 2);
            time_t   lsent  = static_cast<time_t>(sqlite3_column_int64(stmt, 3));
            uint64_t key    = ((uint64_t)dev << 32) | sidx;
            g_cache.sensor_alarm_state[key]     = astate;
            g_cache.sensor_alarm_last_sent[key] = lsent;
            ++n;
        }
        sqlite3_finalize(stmt);
        syslog(LOG_INFO, "state_db: loaded %u sensor alarm state(s)", n);
    }

    // Load SATA attr alarm set.
    const char *sql5 = "SELECT dev_id, attr_id FROM sata_attr_alarm;";
    if (sqlite3_prepare_v2(g_db, sql5, -1, &stmt, nullptr) == SQLITE_OK) {
        unsigned n = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint32_t dev    = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            uint32_t attr   = static_cast<uint32_t>(sqlite3_column_int64(stmt, 1));
            g_cache.sata_attr_alarm[dev].push_back(attr);
            ++n;
        }
        sqlite3_finalize(stmt);
        syslog(LOG_INFO, "state_db: loaded %u SATA attr alarm(s)", n);
    }

    // Load SAS uncorrected baseline.
    const char *sql6 =
        "SELECT dev_id, direction, uncorrected FROM sas_uncorrected_baseline;";
    if (sqlite3_prepare_v2(g_db, sql6, -1, &stmt, nullptr) == SQLITE_OK) {
        unsigned n = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint32_t dev  = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            int      dir  = sqlite3_column_int(stmt, 1);
            uint64_t unc  = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
            uint64_t key  = ((uint64_t)dev << 32) | (uint32_t)dir;
            g_cache.sas_uncorrected_baseline[key] = unc;
            ++n;
        }
        sqlite3_finalize(stmt);
        syslog(LOG_INFO, "state_db: loaded %u SAS uncorrected baseline(s)", n);
    }

    // Load SATA self-test progress state.
    const char *sql7 =
        "SELECT dev_id, start_ns, last_remaining, polling_min, estimated_completion"
        " FROM sata_selftest_progress;";
    if (sqlite3_prepare_v2(g_db, sql7, -1, &stmt, nullptr) == SQLITE_OK) {
        unsigned n = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint32_t dev  = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            AgentxCache::SataSelftestProgress p;
            p.start_ns            = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
            p.last_remaining      = static_cast<uint32_t>(sqlite3_column_int64(stmt, 2));
            p.polling_min         = static_cast<uint32_t>(sqlite3_column_int64(stmt, 3));
            p.estimated_completion= static_cast<time_t>(sqlite3_column_int64(stmt, 4));
            g_cache.sata_selftest_progress[dev] = p;
            ++n;
        }
        sqlite3_finalize(stmt);
        syslog(LOG_INFO, "state_db: loaded %u self-test progress state(s)", n);
    }
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

void state_db_update_by_dev(uint32_t dev_id, uint32_t table_id, uint64_t hash, time_t ts) {
    if (!g_db) return;
    const char *sql =
        "INSERT OR REPLACE INTO sata_by_dev_state (dev_id, table_id, hash, last_change)"
        " VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(table_id));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(hash));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(ts));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_update_devstat_page(uint32_t dev_id, uint32_t page_num,
                                  uint64_t hash, time_t ts) {
    if (!g_db) return;
    const char *sql =
        "INSERT OR REPLACE INTO sata_devstat_page_state"
        " (dev_id, page_num, hash, last_change)"
        " VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(page_num));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(hash));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(ts));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_update_sensor_alarm(uint32_t dev_id, uint32_t sensor_idx,
                                  int alarm_state, time_t last_sent) {
    if (!g_db) return;
    const char *sql =
        "INSERT OR REPLACE INTO sensor_alarm_state"
        " (dev_id, sensor_idx, alarm_state, last_sent)"
        " VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(sensor_idx));
    sqlite3_bind_int(stmt,  3, alarm_state);
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(last_sent));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_set_sata_attr_alarm(uint32_t dev_id, uint32_t attr_id, bool failing) {
    if (!g_db) return;
    const char *sql = failing
        ? "INSERT OR IGNORE INTO sata_attr_alarm (dev_id, attr_id) VALUES (?, ?);"
        : "DELETE FROM sata_attr_alarm WHERE dev_id = ? AND attr_id = ?;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(attr_id));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_update_sas_uncorrected_baseline(uint32_t dev_id, int direction,
                                              uint64_t uncorrected) {
    if (!g_db) return;
    const char *sql =
        "INSERT OR REPLACE INTO sas_uncorrected_baseline"
        " (dev_id, direction, uncorrected)"
        " VALUES (?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_bind_int(stmt,  2, direction);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(uncorrected));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_update_selftest_progress(uint32_t dev_id, uint64_t start_ns,
                                       uint32_t last_remaining, uint32_t polling_min,
                                       time_t estimated_completion) {
    if (!g_db) return;
    const char *sql =
        "INSERT OR REPLACE INTO sata_selftest_progress"
        " (dev_id, start_ns, last_remaining, polling_min, estimated_completion)"
        " VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(start_ns));
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(last_remaining));
    sqlite3_bind_int64(stmt, 4, static_cast<sqlite3_int64>(polling_min));
    sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(estimated_completion));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_clear_selftest_progress(uint32_t dev_id) {
    if (!g_db) return;
    const char *sql = "DELETE FROM sata_selftest_progress WHERE dev_id = ?;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void state_db_remove_device(uint32_t dev_id) {
    if (!g_db) return;
    const char *sqls[] = {
        "DELETE FROM sata_by_dev_state       WHERE dev_id = ?;",
        "DELETE FROM sata_devstat_page_state WHERE dev_id = ?;",
        "DELETE FROM sensor_alarm_state      WHERE dev_id = ?;",
        "DELETE FROM sata_attr_alarm          WHERE dev_id = ?;",
        "DELETE FROM sas_uncorrected_baseline  WHERE dev_id = ?;",
        "DELETE FROM sata_selftest_progress    WHERE dev_id = ?;",
    };
    for (const char *sql : sqls) {
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, nullptr) != SQLITE_OK) continue;
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(dev_id));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void state_db_close() {
    if (g_db) {
        syslog(LOG_INFO, "state_db: closing '%s'", g_db_path.c_str());
        sqlite3_close(g_db);
        g_db = nullptr;
        g_db_path.clear();
    }
}
