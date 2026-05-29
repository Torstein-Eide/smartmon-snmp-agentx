// test_datasrc.cpp — integration tests: parse fixture files → verify cache
//
// Includes agentxd_datasrc.cpp directly (with syslog stubbed) so the full
// production parse path is exercised — no parsing logic is duplicated here.

#include "test_util.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

// Stub syslog so we can link without the full daemon infrastructure.
// Must use C linkage because agentxd_datasrc.cpp includes <syslog.h> inside
// the #define syslog syslog_stub region, which would produce a linkage conflict
// if syslog_stub were declared with C++ linkage.
extern "C" void syslog_stub(int, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

#define syslog syslog_stub
int      g_verbosity             = 0;
uint32_t g_poll_failure_threshold = 1;
#include "../src/agentxd_cache.cpp"
#include "../src/agentxd_json.cpp"

#include "../src/agentxd_notify.h"

struct NotifyCall {
    std::string type;
    uint32_t    dev_idx { 0 };
    int         int_arg { 0 };
    uint32_t    uint_arg { 0 };
    std::string str1;
    uint64_t    u64_arg { 0 };
};

static std::vector<NotifyCall> g_notify_calls;
static void clear_notify_calls() { g_notify_calls.clear(); }

static const NotifyCall *find_call(const std::string &type) {
    for (auto &c : g_notify_calls)
        if (c.type == type) return &c;
    return nullptr;
}

void notify_device_health_changed(uint32_t dev_idx, int new_status) {
    g_notify_calls.push_back({"health_changed", dev_idx, new_status, 0, {}, 0});
}
void notify_device_polling_failed(uint32_t dev_idx, int poll_result) {
    g_notify_calls.push_back({"poll_failed", dev_idx, poll_result, 0, {}, 0});
}
void notify_nvme_selftest_failed(uint32_t dev_idx, const CacheNvmeSelfTestRow &st) {
    NotifyCall c; c.type = "nvme_selftest_failed"; c.dev_idx = dev_idx;
    c.int_arg = st.result; c.uint_arg = st.number; c.str1 = st.result_text;
    g_notify_calls.push_back(c);
}
void notify_sata_selftest_failed(uint32_t dev_idx, const CacheSataSelfTestRow &st) {
    NotifyCall c; c.type = "sata_selftest_failed"; c.dev_idx = dev_idx;
    c.int_arg = st.result; c.uint_arg = st.entry_index;
    g_notify_calls.push_back(c);
}
void notify_sas_selftest_failed(uint32_t dev_idx, const CacheSasSelfTestRow &st) {
    NotifyCall c; c.type = "sas_selftest_failed"; c.dev_idx = dev_idx;
    c.int_arg = st.result; c.uint_arg = st.entry_index;
    g_notify_calls.push_back(c);
}
void notify_device_discovered(uint32_t dev_idx) {
    g_notify_calls.push_back({"discovered", dev_idx, 0, 0, {}, 0});
}
void notify_device_removed(uint32_t dev_idx, const std::string &name,
                           const std::string &, int dev_type) {
    NotifyCall c; c.type = "removed"; c.dev_idx = dev_idx;
    c.int_arg = dev_type; c.str1 = name;
    g_notify_calls.push_back(c);
}
void notify_sata_attr_failing(uint32_t dev_idx, const CacheSataAttrRow &attr) {
    NotifyCall c; c.type = "sata_attr_failing"; c.dev_idx = dev_idx;
    c.uint_arg = attr.attr_id; c.str1 = attr.name;
    g_notify_calls.push_back(c);
}
void notify_sas_uncorrected_errors_increased(uint32_t dev_idx,
                                             const CacheSasErrorCounterRow &ec) {
    NotifyCall c; c.type = "sas_uncorrected"; c.dev_idx = dev_idx;
    c.int_arg = ec.direction; c.u64_arg = ec.uncorrected;
    g_notify_calls.push_back(c);
}
void notify_sensor_high_critical(uint32_t dev_idx, const CacheSensorRow &sensor) {
    g_notify_calls.push_back({"sensor_high_critical", dev_idx, sensor.value, sensor.sensor_index, sensor.name, 0});
}
void notify_sensor_high_warning(uint32_t dev_idx, const CacheSensorRow &sensor) {
    g_notify_calls.push_back({"sensor_high_warning", dev_idx, sensor.value, sensor.sensor_index, sensor.name, 0});
}
void notify_sensor_low_warning(uint32_t dev_idx, const CacheSensorRow &sensor) {
    g_notify_calls.push_back({"sensor_low_warning", dev_idx, sensor.value, sensor.sensor_index, sensor.name, 0});
}
void notify_sensor_low_critical(uint32_t dev_idx, const CacheSensorRow &sensor) {
    g_notify_calls.push_back({"sensor_low_critical", dev_idx, sensor.value, sensor.sensor_index, sensor.name, 0});
}

// Stub state_db — no SQLite in the unit test binary
#include "../src/agentxd_state_db.h"
bool  state_db_open(const std::string &)                                    { return true; }
void  state_db_load()                                                        {}
void  state_db_update(int, uint64_t, time_t)                                 {}
void  state_db_update_by_dev(uint32_t, uint32_t, uint64_t, time_t)          {}
void  state_db_update_devstat_row(uint32_t, uint32_t, uint32_t, uint64_t, time_t) {}
void  state_db_remove_device(uint32_t)                                       {}
void  state_db_close()                                                        {}

#include "../src/agentxd_datasrc.cpp"
#undef syslog

#include "../src/agentxd_cache.h"
#include "../src/agentxd_datasrc.h"
#include "../src/agentxd_json.h"

// ---------------------------------------------------------------------------
// Load a fixture file and return the device index (0 on failure)
// ---------------------------------------------------------------------------

static uint32_t load_fixture(const std::string &path) {
    std::string err;
    JVal root = json_load_file(path, err);
    if (!err.empty()) { fprintf(stderr, "load_fixture: %s\n", err.c_str()); return 0; }
    std::string dev_path = root["device"]["name"].as_string();
    agentxd_datasrc_load_file(path);
    for (const auto &d : g_cache.devices)
        if (d.path == dev_path) return d.index;
    fprintf(stderr, "load_fixture: device '%s' not found in cache after load\n", dev_path.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

static void test_nvme_health(const char *path) {
    SECTION("NVMe health cache");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);

    // Check device row
    bool found_dev = false;
    for (const auto &d : g_cache.devices) {
        if (d.index != idx) continue;
        found_dev = true;
        CHECK_EQ(d.proto, PROTO_NVME);
        CHECK(!d.path.empty());
        CHECK(d.last_poll_time > 0);
        break;
    }
    CHECK(found_dev);

    // Check health row
    bool found_h = false;
    for (const auto &h : g_cache.nvme_health) {
        if (h.device_index != idx) continue;
        found_h = true;
        CHECK(h.overall_status == 1);  // passed=true → 1
        CHECK_EQ(h.critical_warning, 0u);
        CHECK_EQ(h.available_spare_pct, 100u);
        CHECK_EQ(h.available_spare_thresh, 10u);
        CHECK(h.power_on_hours > 0u);
        // data_bytes = data_units * 512000
        CHECK_EQ(h.data_bytes_read, h.data_units_read * 512000ULL);
        CHECK_EQ(h.data_bytes_written, h.data_units_written * 512000ULL);
        break;
    }
    CHECK(found_h);

    // Sensor 2: available spare percentage
    {
        bool found = false;
        for (const auto &s : g_cache.sensors) {
            if (s.device_index != idx || s.sensor_index != 2) continue;
            found = true;
            CHECK_EQ(s.type, 10);        // percent
            CHECK_EQ(s.value, (int32_t)100);
            CHECK(s.has_low_critical);
            CHECK_EQ(s.low_critical, 10); // available_spare_threshold
            CHECK(s.has_low_warning);
            CHECK_EQ(s.low_warning, 20);  // 100% higher than critical
            break;
        }
        CHECK(found);
    }
}

static void test_nvme_selftest(const char *path) {
    SECTION("NVMe self-test cache");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);
    size_t count = 0;
    for (const auto &r : g_cache.nvme_selftests)
        if (r.device_index == idx) ++count;
    CHECK(count >= 2u);

    // First entry: Short, completed without error
    for (const auto &r : g_cache.nvme_selftests) {
        if (r.device_index != idx || r.entry_index != 1) continue;
        CHECK_EQ(r.type, 1);   // short
        CHECK_EQ(r.result, 0); // completed without error
        CHECK(!r.result_text.empty());
        CHECK(r.power_on_hours > 0u);
        break;
    }
}

static void test_ata_attrs(const char *path) {
    SECTION("ATA attribute cache");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);

    size_t count = 0;
    for (const auto &a : g_cache.sata_attrs)
        if (a.device_index == idx) ++count;
    CHECK(count >= 10u);

    // Find Power_On_Hours (id=9) and check raw value is > 0
    bool found_poh = false;
    for (const auto &a : g_cache.sata_attrs) {
        if (a.device_index != idx || a.attr_id != 9) continue;
        found_poh = true;
        CHECK_STR(a.name, "Power_On_Hours");
        CHECK(a.raw_value > 0);
        break;
    }
    CHECK(found_poh);

    if (std::string(path).find("SAMSUNG_MZ7LH960HAJR") != std::string::npos) {
        bool found_temp = false;
        for (const auto &s : g_cache.sensors) {
            if (s.device_index != idx || s.sensor_index != 1) continue;
            found_temp = true;
            CHECK_EQ(s.type, 3);           // celsius
            CHECK(s.has_high_warning);
            CHECK_EQ(s.high_warning, 60);  // SSD warning default remains unchanged
            CHECK(s.has_high_critical);
            CHECK_EQ(s.high_critical, 70); // SSD critical default
            CHECK(s.has_low_warning);
            CHECK_EQ(s.low_warning, 5);
            CHECK(s.has_low_critical);
            CHECK_EQ(s.low_critical, 1);
            break;
        }
        CHECK(found_temp);
    }
}

static void test_ata_selftest(const char *path) {
    SECTION("ATA self-test cache");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);

    size_t count = 0;
    for (const auto &r : g_cache.sata_selftests)
        if (r.device_index == idx) ++count;
    CHECK_EQ(count, 3u);

    // Third entry (entry_index=3): failure
    for (const auto &r : g_cache.sata_selftests) {
        if (r.device_index != idx || r.entry_index != 3) continue;
        CHECK(r.passed == false);
        CHECK_EQ(r.lba_first_error, 123456789ULL);
        break;
    }
}

static void test_scsi_health(const char *path) {
    SECTION("SCSI health cache");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);

    bool found_h = false;
    for (const auto &h : g_cache.sas_health) {
        if (h.device_index != idx) continue;
        found_h = true;
        CHECK_EQ(h.overall_status, 1);         // passed
        CHECK_EQ(h.grown_defect_count, 3u);
        break;
    }
    CHECK(found_h);

    // Error counters: 2 directions (read + write)
    size_t ec_count = 0;
    for (const auto &ec : g_cache.sas_error_counters)
        if (ec.device_index == idx) ++ec_count;
    CHECK_EQ(ec_count, 2u);

    // Self-test entries: 2
    size_t st_count = 0;
    for (const auto &st : g_cache.sas_selftests)
        if (st.device_index == idx) ++st_count;
    CHECK_EQ(st_count, 2u);

    // Both self-tests passed
    for (const auto &st : g_cache.sas_selftests) {
        if (st.device_index != idx) continue;
        CHECK(st.passed);
    }
}

static void test_sata_new_tables(const char *path) {
    SECTION("SATA new tables (ERC, PHY event, selective, log dir, dev stats, health ext)");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);

    // ERC: 2 rows (read + write), both enabled, deciseconds=70
    size_t erc_count = 0;
    for (const auto &r : g_cache.sata_erc) {
        if (r.device_index != idx) continue;
        ++erc_count;
        CHECK(r.enabled);
        CHECK_EQ(r.deciseconds, 70u);
    }
    CHECK_EQ(erc_count, 2u);

    // PHY events: 12 rows, first id=1
    size_t phy_count = 0;
    bool found_phy1 = false;
    for (const auto &r : g_cache.sata_phy_events) {
        if (r.device_index != idx) continue;
        ++phy_count;
        if (r.id == 1) { found_phy1 = true; CHECK(!r.name.empty()); }
    }
    CHECK_EQ(phy_count, 12u);
    CHECK(found_phy1);

    // Selective: 5 rows, all status "Not_testing"
    size_t sel_count = 0;
    for (const auto &r : g_cache.sata_selective_tests) {
        if (r.device_index != idx) continue;
        ++sel_count;
        CHECK_EQ(r.lba_min, 0u);
        CHECK_EQ(r.lba_max, 0u);
        CHECK_STR(r.status_string, "Not_testing");
    }
    CHECK_EQ(sel_count, 5u);

    // Log dir: known addresses 0, 1, 4, 17
    bool found_addr0 = false, found_addr1 = false, found_addr4 = false, found_addr17 = false;
    for (const auto &r : g_cache.sata_log_dir) {
        if (r.device_index != idx) continue;
        if (r.address == 0)  { found_addr0  = true; CHECK(r.readable); }
        if (r.address == 1)  { found_addr1  = true; }
        if (r.address == 4)  { found_addr4  = true; }
        if (r.address == 17) { found_addr17 = true; CHECK(r.writable); }
    }
    CHECK(found_addr0);
    CHECK(found_addr1);
    CHECK(found_addr4);
    CHECK(found_addr17);

    // Dev stats: General Statistics page (1)
    bool found_poh_stat = false;
    for (const auto &r : g_cache.sata_dev_stats) {
        if (r.device_index != idx) continue;
        if (r.page_num == 1 && r.name == "Power-on Hours") {
            found_poh_stat = true;
            CHECK(r.flags_value & 0x40u); // valid bit (ACS bit 6)
            CHECK(r.value > 0u);
        }
    }
    CHECK(found_poh_stat);

    // Info row: new fields
    for (const auto &info : g_cache.sata_info) {
        if (info.device_index != idx) continue;
        CHECK(info.apm_enabled);
        CHECK_EQ(info.apm_level, 254u);
        CHECK_STR(info.apm_string, "maximum performance");
        CHECK_EQ(info.attr_revision, 1u);
        CHECK_EQ(info.ata_version_major, 1020u);
        CHECK_EQ(info.ata_version_minor, 41u);
        CHECK_EQ(info.if_speed_current_mbps, 6000u);
        CHECK_EQ(info.if_speed_max_mbps, 6000u);
        CHECK(info.read_lookahead_enabled);
        CHECK(!info.security_enabled);
        CHECK(!info.security_frozen);
        CHECK_EQ(info.security_state, 1u);
        CHECK_EQ(info.user_capacity_blocks, 27344764928ULL);
        CHECK(info.write_cache_enabled);
        CHECK_EQ(info.sct_hist_op_limit_min, 0);
        CHECK_EQ(info.sct_hist_op_limit_max, 70);
        CHECK_EQ(info.sct_hist_limit_min, 0);
        CHECK_EQ(info.sct_hist_limit_max, 70);
        break;
    }

    // Sensor 2: spare_available.current_percent
    {
        bool found = false;
        for (const auto &s : g_cache.sensors) {
            if (s.device_index != idx || s.sensor_index != 2) continue;
            found = true;
            CHECK_EQ(s.type, 10);         // percent
            CHECK_EQ(s.value, (int32_t)100);
            CHECK(s.has_low_critical);
            CHECK_EQ(s.low_critical, 1);  // threshold_percent
            CHECK(s.has_low_warning);
            CHECK_EQ(s.low_warning, 2);   // 100% higher than critical
            break;
        }
        CHECK(found);
    }

    // Sensor 1: HDD temperature defaults with manufacturer critical overrides.
    {
        bool found = false;
        for (const auto &s : g_cache.sensors) {
            if (s.device_index != idx || s.sensor_index != 1) continue;
            found = true;
            CHECK_EQ(s.type, 3);          // celsius
            CHECK(s.has_high_warning);
            CHECK_EQ(s.high_warning, 45); // HDD warning default remains unchanged
            CHECK(s.has_high_critical);
            CHECK_EQ(s.high_critical, 65); // temperature.op_limit_max
            CHECK(s.has_low_warning);
            CHECK_EQ(s.low_warning, 5);   // HDD warning default remains unchanged
            CHECK(s.has_low_critical);
            CHECK_EQ(s.low_critical, 0);  // temperature.op_limit_min
            break;
        }
        CHECK(found);
    }

    // Pending defects LBA table: 1 row, lba = 12345678901
    {
        size_t pd_count = 0;
        bool found_lba = false;
        for (const auto &r : g_cache.sata_pending_defects) {
            if (r.device_index != idx) continue;
            ++pd_count;
            if (r.entry_index == 1) { found_lba = true; CHECK_EQ(r.lba, 12345678901ULL); }
        }
        CHECK_EQ(pd_count, 1u);
        CHECK(found_lba);
    }

    // Health row: new fields
    for (const auto &h : g_cache.sata_health) {
        if (h.device_index != idx) continue;
        CHECK_EQ(h.spare_available_pct, 100u);
        CHECK_EQ(h.pending_defects_count, 0u);
        CHECK_EQ(h.error_log_revision, 1u);
        CHECK_EQ(h.selftest_log_count, 19u);
        CHECK_EQ(h.selftest_log_err_total, 0u);
        // cap fields (sub-OIDs 23-26)
        CHECK(h.cap_exec_offline_immediate);
        CHECK(!h.cap_offline_aborted_on_cmd);
        CHECK(h.cap_offline_surface_scan);
        CHECK(h.cap_attr_autosave);
        // selective scalars
        CHECK_EQ(h.selective_log_revision, 1u);
        // logdir scalars
        CHECK_EQ(h.logdir_gp_version, 1u);
        CHECK_EQ(h.sct_status_format_version, 3u);
        CHECK_EQ(h.sct_status_sct_version, 256u);
        CHECK_EQ(h.sct_status_device_state, 0u);
        CHECK_EQ(h.sct_temp_power_cycle_min, 39);
        CHECK_EQ(h.sct_temp_power_cycle_max, 45);
        CHECK_EQ(h.sct_temp_lifetime_min, 22);
        CHECK_EQ(h.sct_temp_lifetime_max, 53);
        CHECK_EQ(h.sct_temp_under_limit_count, 0u);
        CHECK_EQ(h.sct_temp_over_limit_count, 0u);
        CHECK(h.sct_smart_status_passed);
        break;
    }
}

static void test_cache_remove() {
    SECTION("cache remove_device");
    size_t initial_devs = g_cache.devices.size();
    uint32_t idx = g_cache.upsert_device("/dev/test_remove", PROTO_ATA, 0);
    CHECK(g_cache.devices.size() == initial_devs + 1);
    g_cache.remove_device(idx);
    CHECK(g_cache.devices.size() == initial_devs);
    // Verify not found after removal
    for (const auto &d : g_cache.devices)
        CHECK(d.index != idx);
}

static void test_cache_upsert() {
    SECTION("cache upsert idempotence");
    uint32_t idx1 = g_cache.upsert_device("/dev/upsert_test", PROTO_NVME, 0);
    uint32_t idx2 = g_cache.upsert_device("/dev/upsert_test", PROTO_NVME, 0);
    CHECK_EQ(idx1, idx2);
    size_t count_before = g_cache.devices.size();
    g_cache.upsert_device("/dev/upsert_test", PROTO_NVME, 0);
    CHECK_EQ(g_cache.devices.size(), count_before);
    // Update proto
    uint32_t idx3 = g_cache.upsert_device("/dev/upsert_test", PROTO_SAT, 0);
    CHECK_EQ(idx1, idx3);
    for (const auto &d : g_cache.devices)
        if (d.index == idx1) { CHECK_EQ(d.proto, PROTO_SAT); break; }
    g_cache.remove_device(idx1);
}

// ---------------------------------------------------------------------------
// Helpers for SATA hash isolation test
// ---------------------------------------------------------------------------

// Snapshot of all 12 SATA global table hashes, computed live from g_cache.
// hash_vector() is the same function used by parse_sata internals.
struct SataHashes {
    uint64_t h[12];  // indexed 0..11 matching SATA_TBL_* below

    static SataHashes capture() {
        SataHashes s;
        s.h[0]  = hash_vector(g_cache.sata_info);
        s.h[1]  = hash_vector(g_cache.sata_health);
        s.h[2]  = hash_vector(g_cache.sata_attrs);
        s.h[3]  = hash_vector(g_cache.sata_error_log);
        s.h[4]  = hash_vector(g_cache.sata_error_cmds);
        s.h[5]  = hash_vector(g_cache.sata_selftests);
        s.h[6]  = hash_vector(g_cache.sata_erc);
        s.h[7]  = hash_vector(g_cache.sata_phy_events);
        s.h[8]  = hash_vector(g_cache.sata_selective_tests);
        s.h[9]  = hash_vector(g_cache.sata_pending_defects);
        s.h[10] = hash_vector(g_cache.sata_log_dir);
        s.h[11] = hash_vector(g_cache.sata_dev_stats);
        return s;
    }
};

enum {
    SATA_TBL_INFO=0, SATA_TBL_HEALTH, SATA_TBL_ATTR,
    SATA_TBL_ERRLOG, SATA_TBL_ERRCMD, SATA_TBL_SELFTEST,
    SATA_TBL_ERC,    SATA_TBL_PHY,    SATA_TBL_SELTEST,
    SATA_TBL_PENDING,SATA_TBL_LOGDIR, SATA_TBL_DEVSTAT,
    SATA_TBL_COUNT
};
static const char *sata_tbl_name[] = {
    "sata_info","sata_health","sata_attr",
    "sata_error_log","sata_error_cmd","sata_selftest",
    "sata_erc","sata_phy_event","sata_selective_test",
    "sata_pending_defects","sata_log_dir","sata_dev_stat"
};

// Verify that exactly one global table hash changed between before and after.
static void check_hash_isolation(const SataHashes &before, const SataHashes &after,
                                  int expected_changed) {
    for (int i = 0; i < SATA_TBL_COUNT; i++) {
        if (i == expected_changed) {
            if (after.h[i] == before.h[i]) {
                ++s_fail;
                fprintf(stderr, "FAIL %s:%d: %s hash should have changed but didn't\n",
                        __FILE__, __LINE__, sata_tbl_name[i]);
            } else {
                ++s_pass;
            }
        } else {
            if (after.h[i] != before.h[i]) {
                ++s_fail;
                fprintf(stderr, "FAIL %s:%d: %s hash changed spuriously"
                        " (expected only %s to change)\n",
                        __FILE__, __LINE__, sata_tbl_name[i],
                        sata_tbl_name[expected_changed]);
            } else {
                ++s_pass;
            }
        }
    }
}

template<typename Vec>
static typename Vec::value_type *find_dev_row(Vec &v, uint32_t dev_idx) {
    for (auto &r : v) if (r.device_index == dev_idx) return &r;
    return nullptr;
}

// Explicit helper: check isolation for smartmonSataErrorCmdTable (3-level).
// Mutates timestamp_ms on the first row belonging to dev_idx.
static void check_errcmd_isolation(uint32_t dev_idx, uint32_t other_dev_idx) {
    auto *row = find_dev_row(g_cache.sata_error_cmds, dev_idx);
    if (!row) return;  // device has no error commands — skip

    auto g_before    = SataHashes::capture();
    uint64_t self_before  = hash_vector_for_device(g_cache.sata_error_cmds, dev_idx);
    uint64_t other_before = hash_vector_for_device(g_cache.sata_error_cmds, other_dev_idx);

    ++(row->timestamp_ms);

    auto g_after     = SataHashes::capture();
    uint64_t self_after   = hash_vector_for_device(g_cache.sata_error_cmds, dev_idx);
    uint64_t other_after  = hash_vector_for_device(g_cache.sata_error_cmds, other_dev_idx);

    check_hash_isolation(g_before, g_after, SATA_TBL_ERRCMD);
    CHECK(self_after  != self_before);   // mutated device per-device hash changed
    CHECK(other_after == other_before);  // other device per-device hash unchanged

    --(row->timestamp_ms);
}

// Explicit helper: check isolation for smartmonSataDevStatTable (3-level).
// Mutates value on the first row belonging to dev_idx.
static void check_devstat_isolation(uint32_t dev_idx, uint32_t other_dev_idx) {
    auto *row = find_dev_row(g_cache.sata_dev_stats, dev_idx);
    if (!row) return;  // device has no dev stats — skip

    auto g_before    = SataHashes::capture();
    uint64_t self_before  = hash_vector_for_device(g_cache.sata_dev_stats, dev_idx);
    uint64_t other_before = hash_vector_for_device(g_cache.sata_dev_stats, other_dev_idx);

    ++(row->value);

    auto g_after     = SataHashes::capture();
    uint64_t self_after   = hash_vector_for_device(g_cache.sata_dev_stats, dev_idx);
    uint64_t other_after  = hash_vector_for_device(g_cache.sata_dev_stats, other_dev_idx);

    check_hash_isolation(g_before, g_after, SATA_TBL_DEVSTAT);
    CHECK(self_after  != self_before);   // mutated device per-device hash changed
    CHECK(other_after == other_before);  // other device per-device hash unchanged

    --(row->value);
}

// Run mutation checks on one device's rows.
// For all 12 global tables: increment one field, verify only that table's hash
// changed, restore. For the two 3-level tables (errcmd, devstat): additionally
// verify per-device hash isolation against other_dev_idx (pass 0 when testing
// single-device — other_dev_idx's hash will be empty/stable in that case).
static void check_per_table_isolation(uint32_t dev_idx, uint32_t other_dev_idx = 0) {
#define MUTATE(vec, field, tbl_idx) \
    do { \
        auto *row = find_dev_row(g_cache.vec, dev_idx); \
        if (row) { \
            auto before = SataHashes::capture(); \
            ++(row->field); \
            auto after = SataHashes::capture(); \
            check_hash_isolation(before, after, tbl_idx); \
            --(row->field); \
        } \
    } while (0)

    // 10 level-2 tables (no per-device tracking):
    MUTATE(sata_info,            rotation_rate,   SATA_TBL_INFO);
    MUTATE(sata_health,          power_cycles,    SATA_TBL_HEALTH);
    MUTATE(sata_attrs,           raw_value,       SATA_TBL_ATTR);
    MUTATE(sata_error_log,       error_number,    SATA_TBL_ERRLOG);
    MUTATE(sata_selftests,       lifetime_hours,  SATA_TBL_SELFTEST);
    MUTATE(sata_erc,             deciseconds,     SATA_TBL_ERC);
    MUTATE(sata_phy_events,      value,           SATA_TBL_PHY);
    MUTATE(sata_selective_tests, lba_min,         SATA_TBL_SELTEST);
    MUTATE(sata_pending_defects, lba,             SATA_TBL_PENDING);
    MUTATE(sata_log_dir,         gp_sectors,      SATA_TBL_LOGDIR);
#undef MUTATE

    // 2 level-3 tables (global + per-device hash isolation):
    check_errcmd_isolation(dev_idx, other_dev_idx);
    check_devstat_isolation(dev_idx, other_dev_idx);
}

// ---------------------------------------------------------------------------
// Main test: per-table hash isolation + multi-device re-parse stability
// ---------------------------------------------------------------------------

static void test_sata_multidevice_stable_hashes(const char *path_a, const char *path_b) {
    SECTION("SATA: per-table hash isolation and multi-device re-parse stability");
    bool prev_scan = s_initial_scan_done;
    s_initial_scan_done = false;
    g_cache.clear();
    // clear() resets ts_* but not table_hashes — reset manually so initial
    // loads always produce a hash change (matching the daemon's cold-start).
    for (auto &h : g_cache.table_hashes) h = 0;
    clear_notify_calls();

    // === Phase 1: single device A ===
    uint32_t idx_a = load_fixture(path_a);
    CHECK(idx_a > 0);

    SECTION("SATA: device A alone — mutating each table changes only that table's hash");
    check_per_table_isolation(idx_a, 0);

    // === Phase 2: add device B ===
    uint32_t idx_b = load_fixture(path_b);
    CHECK(idx_b > 0);
    CHECK(idx_a != idx_b);

    SECTION("SATA: device B added — mutating each table changes only that table's hash"
            " (3-level tables: per-device hash of other device must not change)");
    check_per_table_isolation(idx_b, idx_a);

    // === Phase 3: re-parse device A unchanged — stored hashes must not change ===
    // Snapshot everything that parse_sata persists in g_cache.table_hashes,
    // the ts_* timestamps, and the per-device maps for the two 3-level tables.
    uint64_t snap[TABLE_COUNT];
    for (int i = 0; i < TABLE_COUNT; i++) snap[i] = g_cache.table_hashes[i];

    time_t ts_snap_info    = g_cache.ts_sata_info;
    time_t ts_snap_health  = g_cache.ts_sata_health;
    time_t ts_snap_attr    = g_cache.ts_sata_attr;
    time_t ts_snap_errlog  = g_cache.ts_sata_error_log;
    time_t ts_snap_errcmd  = g_cache.ts_sata_error_cmd;
    time_t ts_snap_selftest= g_cache.ts_sata_selftest;
    time_t ts_snap_erc     = g_cache.ts_sata_erc;
    time_t ts_snap_phy     = g_cache.ts_sata_phy_event;
    time_t ts_snap_seltest = g_cache.ts_sata_selective_test;
    time_t ts_snap_pending = g_cache.ts_sata_pending_defects;
    time_t ts_snap_logdir  = g_cache.ts_sata_log_dir;
    time_t ts_snap_devstat = g_cache.ts_sata_dev_stat;

    // Per-device hash/ts snapshots for errcmd (tableId=5) via ts_sata_by_dev.
    auto errcmd_key = [](uint32_t dev) -> uint64_t { return ((uint64_t)dev << 32) | 5; };
    uint64_t snap_errcmd_a   = g_cache.hash_sata_by_dev[errcmd_key(idx_a)];
    uint64_t snap_errcmd_b   = g_cache.hash_sata_by_dev[errcmd_key(idx_b)];
    time_t ts_snap_errcmd_a  = g_cache.ts_sata_by_dev[errcmd_key(idx_a)];
    time_t ts_snap_errcmd_b  = g_cache.ts_sata_by_dev[errcmd_key(idx_b)];

    // Per-row hash/ts snapshots for devstat (both devices).
    std::vector<uint64_t> devstat_keys_a, devstat_keys_b;
    for (const auto &r : g_cache.sata_dev_stats) {
        if (r.device_index == idx_a) devstat_keys_a.push_back(sata_devstat_row_key(idx_a, r.page_num, r.offset));
        if (r.device_index == idx_b) devstat_keys_b.push_back(sata_devstat_row_key(idx_b, r.page_num, r.offset));
    }
    std::unordered_map<uint64_t, uint64_t> snap_devstat_hash_a, snap_devstat_hash_b;
    std::unordered_map<uint64_t, time_t>   snap_devstat_ts_a,   snap_devstat_ts_b;
    for (auto k : devstat_keys_a) {
        snap_devstat_hash_a[k] = g_cache.hash_sata_devstat_by_row[k];
        snap_devstat_ts_a[k]   = g_cache.ts_sata_devstat_by_row[k];
    }
    for (auto k : devstat_keys_b) {
        snap_devstat_hash_b[k] = g_cache.hash_sata_devstat_by_row[k];
        snap_devstat_ts_b[k]   = g_cache.ts_sata_devstat_by_row[k];
    }

    SECTION("SATA: re-parsing device A unchanged with device B in cache —"
            " no global hash, ts, or per-device hash/ts change");
    agentxd_datasrc_load_file(path_a);

    // Global table hashes and timestamps must be stable.
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_INFO],     snap[TABLE_SATA_INFO]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_HEALTH],   snap[TABLE_SATA_HEALTH]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_ATTR],     snap[TABLE_SATA_ATTR]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_ERRLOG],   snap[TABLE_SATA_ERRLOG]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_ERRCMD],   snap[TABLE_SATA_ERRCMD]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_SELFTEST], snap[TABLE_SATA_SELFTEST]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_ERC],      snap[TABLE_SATA_ERC]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_PHY],      snap[TABLE_SATA_PHY]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_SELTEST],  snap[TABLE_SATA_SELTEST]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_PENDING],  snap[TABLE_SATA_PENDING]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_LOGDIR],   snap[TABLE_SATA_LOGDIR]);
    CHECK_EQ(g_cache.table_hashes[TABLE_SATA_DEVSTAT],  snap[TABLE_SATA_DEVSTAT]);

    CHECK_EQ(g_cache.ts_sata_info,            ts_snap_info);
    CHECK_EQ(g_cache.ts_sata_health,          ts_snap_health);
    CHECK_EQ(g_cache.ts_sata_attr,            ts_snap_attr);
    CHECK_EQ(g_cache.ts_sata_error_log,       ts_snap_errlog);
    CHECK_EQ(g_cache.ts_sata_error_cmd,       ts_snap_errcmd);
    CHECK_EQ(g_cache.ts_sata_selftest,        ts_snap_selftest);
    CHECK_EQ(g_cache.ts_sata_erc,             ts_snap_erc);
    CHECK_EQ(g_cache.ts_sata_phy_event,       ts_snap_phy);
    CHECK_EQ(g_cache.ts_sata_selective_test,  ts_snap_seltest);
    CHECK_EQ(g_cache.ts_sata_pending_defects, ts_snap_pending);
    CHECK_EQ(g_cache.ts_sata_log_dir,         ts_snap_logdir);
    CHECK_EQ(g_cache.ts_sata_dev_stat,        ts_snap_devstat);

    // Per-device errcmd (tableId=5) hashes and timestamps must be stable.
    CHECK_EQ(g_cache.hash_sata_by_dev[errcmd_key(idx_a)], snap_errcmd_a);
    CHECK_EQ(g_cache.hash_sata_by_dev[errcmd_key(idx_b)], snap_errcmd_b);
    CHECK_EQ(g_cache.ts_sata_by_dev[errcmd_key(idx_a)],   ts_snap_errcmd_a);
    CHECK_EQ(g_cache.ts_sata_by_dev[errcmd_key(idx_b)],   ts_snap_errcmd_b);

    // Per-row devstat hashes and timestamps must be stable.
    for (auto k : devstat_keys_a) {
        CHECK_EQ(g_cache.hash_sata_devstat_by_row[k], snap_devstat_hash_a[k]);
        CHECK_EQ(g_cache.ts_sata_devstat_by_row[k],   snap_devstat_ts_a[k]);
    }
    for (auto k : devstat_keys_b) {
        CHECK_EQ(g_cache.hash_sata_devstat_by_row[k], snap_devstat_hash_b[k]);
        CHECK_EQ(g_cache.ts_sata_devstat_by_row[k],   snap_devstat_ts_b[k]);
    }

    s_initial_scan_done = prev_scan;
}

static void test_notify_no_discovered_during_startup(const char *path) {
    SECTION("notify: no device_discovered during initial startup scan");
    s_initial_scan_done = false;
    g_cache.clear();
    clear_notify_calls();
    load_fixture(path);
    CHECK(find_call("discovered") == nullptr);
}

static void test_notify_no_discovered_on_datasrc_init_rescan(const char *path) {
    SECTION("notify: no device_discovered during datasource init rescan");
    std::string dir = path;
    size_t slash = dir.rfind('/');
    CHECK(slash != std::string::npos);
    if (slash == std::string::npos)
        return;
    dir.resize(slash);

    s_initial_scan_done = true;
    g_cache.clear();
    clear_notify_calls();
    CHECK(agentxd_datasrc_init(dir));
    agentxd_datasrc_shutdown();
    CHECK(find_call("discovered") == nullptr);
}

static void test_notify_discovered(const char *path) {
    SECTION("notify: device_discovered on first load after startup");
    g_cache.clear();
    clear_notify_calls();
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);
    const NotifyCall *c = find_call("discovered");
    CHECK(c != nullptr);
    if (c) CHECK_EQ(c->dev_idx, idx);
    CHECK(find_call("health_changed") == nullptr);
}

static void test_notify_health_changed(const char *healthy_path,
                                       const char *failing_path) {
    SECTION("notify: health_changed on status transition");
    g_cache.clear();
    load_fixture(healthy_path);
    clear_notify_calls();
    uint32_t idx = load_fixture(failing_path);
    CHECK(idx > 0);
    const NotifyCall *c = find_call("health_changed");
    CHECK(c != nullptr);
    if (c) {
        CHECK_EQ(c->dev_idx, idx);
        CHECK_EQ(c->int_arg, 2);
    }
    CHECK(find_call("discovered") == nullptr);
}

static void test_notify_sata_selftest_failed(const char *nofail_path,
                                             const char *fail_path) {
    SECTION("notify: sata_selftest_failed on new failure entry");
    g_cache.clear();
    load_fixture(nofail_path);
    clear_notify_calls();
    uint32_t idx = load_fixture(fail_path);
    CHECK(idx > 0);
    const NotifyCall *c = find_call("sata_selftest_failed");
    CHECK(c != nullptr);
    if (c) CHECK_EQ(c->dev_idx, idx);
}

static void test_notify_sata_attr_failing(const char *ok_path,
                                          const char *fail_path) {
    SECTION("notify: sata_attr_failing when attr crosses threshold");
    g_cache.clear();
    load_fixture(ok_path);
    clear_notify_calls();
    uint32_t idx = load_fixture(fail_path);
    CHECK(idx > 0);
    const NotifyCall *c = find_call("sata_attr_failing");
    CHECK(c != nullptr);
    if (c) {
        CHECK_EQ(c->dev_idx, idx);
        CHECK_EQ(c->uint_arg, 1u);
    }
}

static void test_notify_nvme_selftest_failed(const char *ok_path,
                                             const char *fail_path) {
    SECTION("notify: nvme_selftest_failed on new failure");
    g_cache.clear();
    load_fixture(ok_path);
    clear_notify_calls();
    uint32_t idx = load_fixture(fail_path);
    CHECK(idx > 0);
    const NotifyCall *c = find_call("nvme_selftest_failed");
    CHECK(c != nullptr);
    if (c) {
        CHECK_EQ(c->dev_idx, idx);
        CHECK(c->int_arg != 0);
        CHECK(!c->str1.empty());
    }
}

static void test_notify_sas_uncorrected(const char *ok_path,
                                        const char *fail_path) {
    SECTION("notify: sas_uncorrected_errors_increased");
    g_cache.clear();
    load_fixture(ok_path);
    clear_notify_calls();
    uint32_t idx = load_fixture(fail_path);
    CHECK(idx > 0);
    const NotifyCall *c = find_call("sas_uncorrected");
    CHECK(c != nullptr);
    if (c) {
        CHECK_EQ(c->dev_idx, idx);
        CHECK_EQ(c->int_arg, 1);
        CHECK_EQ(c->u64_arg, 5u);
    }
}

static void test_notify_device_removed() {
    SECTION("notify: device_removed via agentxd_datasrc_remove_device");
    g_cache.clear();
    uint32_t idx = g_cache.upsert_device("/dev/test_notify_remove", PROTO_ATA, 0);
    for (auto &d : g_cache.devices)
        if (d.index == idx) { d.name = "test_notify_remove"; break; }
    clear_notify_calls();
    agentxd_datasrc_remove_device(idx);
    const NotifyCall *c = find_call("removed");
    CHECK(c != nullptr);
    if (c) {
        CHECK_EQ(c->dev_idx, idx);
        CHECK_STR(c->str1, "test_notify_remove");
    }
    CHECK(g_cache.find_device(idx) == nullptr);
}

// ---------------------------------------------------------------------------
// main
static void test_farm_sensors(const char *path) {
    SECTION("FARM sensor cache");
    uint32_t idx = load_fixture(path);
    CHECK(idx > 0);

    // Collect all sensors for this device
    std::vector<const CacheSensorRow *> rows;
    for (const auto &s : g_cache.sensors)
        if (s.device_index == idx) rows.push_back(&s);

    CHECK_EQ(rows.size(), 6u);  // temp(1) + wear(2) + 12V(3) + 5V(4) + humidity(5) + motor(6)

    // Temperature at sensor_index 1
    bool found_temp = false;
    for (const auto *s : rows) {
        if (s->sensor_index != 1) continue;
        found_temp = true;
        CHECK_EQ(s->type, 3);  // celsius
        break;
    }
    CHECK(found_temp);

    // 12V supply at sensor_index 3
    bool found_12v = false;
    for (const auto *s : rows) {
        if (s->sensor_index != 3) continue;
        found_12v = true;
        CHECK_STR(s->name, "12V Supply");
        CHECK_EQ(s->value, 12189);
        CHECK_EQ(s->type, 6);   // voltsDC
        CHECK_EQ(s->scale, 8);  // milli
        break;
    }
    CHECK(found_12v);
}

// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    // argv[1..] = fixture file paths
    const char *nvme_path         = nullptr;
    const char *nvme_st_path      = nullptr;  // NVMe 980 PRO healthy
    const char *nvme_failing_path = nullptr;
    const char *nvme_stfail_path  = nullptr;
    const char *ata_path          = nullptr;
    const char *ata_st_path       = nullptr;
    const char *ata_stfail_path   = nullptr;
    const char *ata_nofail_path   = nullptr;
    const char *ata_attrfail_path = nullptr;
    const char *scsi_path         = nullptr;
    const char *scsi_uncorr_path  = nullptr;
    const char *wdc_path          = nullptr;  // WDC fixture with new SATA tables
    const char *farm_path         = nullptr;  // Seagate FARM ATA fixture

    for (int i = 1; i < argc; ++i) {
        std::string p = argv[i];
        if (p.find("980_PRO") != std::string::npos) {
            if (p.find(".failing.") != std::string::npos)
                nvme_failing_path = argv[i];
            else if (p.find(".selftest-fail.") != std::string::npos)
                nvme_stfail_path = argv[i];
            else if (!nvme_st_path)
                nvme_st_path = argv[i];
        } else if (p.find(".nvme.json") != std::string::npos && !nvme_path) {
            nvme_path = argv[i];
        } else if (p.find("SELFTESTS") != std::string::npos) {
            if (p.find(".nofail.") != std::string::npos)
                ata_nofail_path = argv[i];
            else if (p.find(".attr-fail.") != std::string::npos)
                ata_attrfail_path = argv[i];
            else if (p.find(".selftest-fail.") != std::string::npos)
                ata_stfail_path = argv[i];
            else if (p.find(".health-fail.") == std::string::npos && !ata_st_path)
                ata_st_path = argv[i];
        } else if (p.find("WDC_WD140EFGX_68B0GN0-81GDJW2V") != std::string::npos) {
            wdc_path = argv[i];
        } else if (p.find(".farm.ata.json") != std::string::npos) {
            farm_path = argv[i];
        } else if (p.find(".ata.json") != std::string::npos && !ata_path) {
            ata_path = argv[i];
        } else if (p.find(".scsi.json") != std::string::npos) {
            if (p.find(".uncorrected.") != std::string::npos)
                scsi_uncorr_path = argv[i];
            else if (p.find(".health-fail.") == std::string::npos
                     && p.find(".selftest-fail.") == std::string::npos
                     && !scsi_path)
                scsi_path = argv[i];
        }
    }

    test_cache_remove();
    test_cache_upsert();

    if (nvme_path)    test_nvme_health(nvme_path);
    if (nvme_st_path) test_nvme_selftest(nvme_st_path);
    if (wdc_path)     test_sata_new_tables(wdc_path);
    if (wdc_path && ata_path) test_sata_multidevice_stable_hashes(wdc_path, ata_path);
    if (farm_path)    test_farm_sensors(farm_path);
    if (ata_path)     test_ata_attrs(ata_path);
    if (ata_st_path)  test_ata_selftest(ata_st_path);
    if (scsi_path)    test_scsi_health(scsi_path);

    test_notify_device_removed();
    if (nvme_st_path)
        test_notify_no_discovered_during_startup(nvme_st_path);
    if (nvme_st_path)
        test_notify_no_discovered_on_datasrc_init_rescan(nvme_st_path);
    s_initial_scan_done = true;
    if (nvme_st_path)
        test_notify_discovered(nvme_st_path);
    if (nvme_st_path && nvme_failing_path)
        test_notify_health_changed(nvme_st_path, nvme_failing_path);
    if (nvme_st_path && nvme_stfail_path)
        test_notify_nvme_selftest_failed(nvme_st_path, nvme_stfail_path);
    if (ata_nofail_path && ata_stfail_path)
        test_notify_sata_selftest_failed(ata_nofail_path, ata_stfail_path);
    if (ata_st_path && ata_attrfail_path)
        test_notify_sata_attr_failing(ata_st_path, ata_attrfail_path);
    if (scsi_path && scsi_uncorr_path)
        test_notify_sas_uncorrected(scsi_path, scsi_uncorr_path);

    return test_summary();
}
