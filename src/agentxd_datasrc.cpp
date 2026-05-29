// agentxd_datasrc.cpp — smartd JSON state file watcher and parser

#include "agentxd_datasrc.h"
#include "agentxd_cache.h"
#include "agentxd_config.h"
#include "agentxd_json.h"
#include "agentxd_notify.h"
#include "agentxd_state_db.h"

#include <algorithm>
#include <numeric>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <string>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

static inline long elapsed_ms(struct timespec start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start.tv_sec) * 1000L
         + (now.tv_nsec - start.tv_nsec) / 1000000L;
}

// ---------------------------------------------------------------------------
// FNV-1a hasher — used to detect content changes in cache vectors
// ---------------------------------------------------------------------------

namespace {

struct TableHasher {
    uint64_t h = 14695981039346656037ULL;
    void feed(const void *p, size_t n) {
        const uint8_t *b = static_cast<const uint8_t *>(p);
        for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
    }
    template<typename T> void feed(T v)           { feed(&v, sizeof(v)); }
    void feed(const std::string &s) { uint64_t n = s.size(); feed(n); feed(s.data(), n); }
    uint64_t value() const { return h; }
};

// Per-row hash helpers (only content fields; internal bookkeeping excluded).
// CacheDeviceRow: exclude last_poll_time, last_json_mtime, consec_fail_count.
static void hash_row(TableHasher &h, const CacheDeviceRow &r) {
    h.feed(r.index); h.feed(r.name); h.feed(r.path); h.feed(static_cast<int>(r.proto));
    h.feed(static_cast<int>(r.poll_result)); h.feed(r.poll_exit_status); h.feed(r.uris);
    h.feed(r.model_family); h.feed(r.model_name); h.feed(r.serial_number);
    h.feed(r.firmware_version); h.feed(r.wwn);
}
static void hash_row(TableHasher &h, const CacheNvmeControllerRow &r) {
    h.feed(r.device_index); h.feed(r.pci_vendor_id); h.feed(r.pci_subsystem_id);
    h.feed(r.pci_vendor_id_text); h.feed(r.pci_subsystem_vendor_text);
    h.feed(r.ieee_oui); h.feed(r.total_capacity); h.feed(r.unallocated_capacity);
    h.feed(r.controller_id); h.feed(r.version_string); h.feed(r.version_value);
    h.feed(r.namespace_count); h.feed(r.max_data_transfer_pages);
}
static void hash_row(TableHasher &h, const CacheNvmeNamespaceRow &r) {
    h.feed(r.device_index); h.feed(r.namespace_id);
    h.feed(r.size_bytes); h.feed(r.capacity_bytes); h.feed(r.utilization_bytes);
    h.feed(r.formatted_lba_size); h.feed(r.size_blocks); h.feed(r.capacity_blocks);
    h.feed(r.utilization_blocks);
}
static void hash_row(TableHasher &h, const CacheNvmeHealthRow &r) {
    h.feed(r.device_index); h.feed(r.overall_status); h.feed(r.critical_warning);
    h.feed(r.available_spare_pct); h.feed(r.available_spare_thresh);
    h.feed(r.percentage_used); h.feed(r.data_units_read); h.feed(r.data_units_written);
    h.feed(r.data_bytes_read); h.feed(r.data_bytes_written);
    h.feed(r.host_read_commands); h.feed(r.host_write_commands);
    h.feed(r.controller_busy_minutes); h.feed(r.power_cycles); h.feed(r.power_on_hours);
    h.feed(r.unsafe_shutdowns); h.feed(r.media_errors); h.feed(r.error_log_entries);
    h.feed(r.warning_temp_minutes); h.feed(r.critical_temp_minutes);
    h.feed(r.current_selftest_value); h.feed(r.current_selftest_str);
}
static void hash_row(TableHasher &h, const CacheNvmeSelfTestRow &r) {
    h.feed(r.device_index); h.feed(r.entry_index); h.feed(r.number);
    h.feed(r.type); h.feed(r.result); h.feed(r.result_text);
    h.feed(r.power_on_hours); h.feed(r.failing_lba); h.feed(r.namespace_id);
    h.feed(r.segment_number); h.feed(r.status_code_type); h.feed(r.status_code);
    h.feed(r.estimated_completion);
}
// error_timestamp excluded: set to daemon's current time, not JSON data.
static void hash_row(TableHasher &h, const CacheNvmeErrorLogRow &r) {
    h.feed(r.device_index); h.feed(r.entry_index); h.feed(r.error_count);
    h.feed(r.sqid); h.feed(r.command_id); h.feed(r.status_field);
    h.feed(r.parm_error_location); h.feed(r.lba); h.feed(r.nsid);
    h.feed(r.status_code); h.feed(r.status_code_type);
    h.feed(r.do_not_retry); h.feed(r.phase_tag); h.feed(r.status_string);
}
static void hash_row(TableHasher &h, const CacheNvmeCapabilityRow &r) {
    h.feed(r.device_index); h.feed(r.firmware_update_raw); h.feed(r.firmware_slot_count);
    h.feed(r.firmware_reset_required); h.feed(r.optional_admin_cmd_raw);
    h.feed(r.optional_nvm_cmd_raw); h.feed(r.log_page_attr_raw);
    h.feed(r.optional_admin_cmd_text); h.feed(r.optional_nvm_cmd_text);
    h.feed(r.log_page_attr_text);
}
static void hash_row(TableHasher &h, const CacheNvmePowerStateRow &r) {
    h.feed(r.device_index); h.feed(r.state_index); h.feed(r.operational);
    h.feed(r.max_power_mw); h.feed(r.has_active_power); h.feed(r.active_power_mw);
    h.feed(r.has_idle_power); h.feed(r.idle_power_mw); h.feed(r.read_latency_rank);
    h.feed(r.read_throughput_rank); h.feed(r.write_latency_rank);
    h.feed(r.write_throughput_rank); h.feed(r.entry_latency_usec); h.feed(r.exit_latency_usec);
}
static void hash_row(TableHasher &h, const CacheNvmeLbaFormatRow &r) {
    h.feed(r.device_index); h.feed(r.namespace_id); h.feed(r.format_id);
    h.feed(r.current); h.feed(r.data_size); h.feed(r.metadata_size); h.feed(r.rel_perf);
}
static void hash_row(TableHasher &h, const CacheSataInfoRow &r) {
    h.feed(r.device_index); h.feed(r.ata_version); h.feed(r.sata_version);
    h.feed(r.form_factor); h.feed(r.rotation_rate); h.feed(r.logical_block_size);
    h.feed(r.physical_block_size); h.feed(r.user_capacity_bytes);
    h.feed(r.in_smartctl_db); h.feed(r.smart_available); h.feed(r.smart_enabled);
    h.feed(r.trim_supported); h.feed(r.user_capacity_blocks);
    h.feed(r.ata_version_major); h.feed(r.ata_version_minor);
    h.feed(r.if_speed_max_mbps); h.feed(r.if_speed_current_mbps);
    h.feed(r.apm_enabled); h.feed(r.apm_level);
    // apm_string excluded: human-readable representation, not exposed via MIB
    h.feed(r.read_lookahead_enabled); h.feed(r.write_cache_enabled);
    h.feed(r.security_state); h.feed(r.security_enabled); h.feed(r.security_frozen);
    h.feed(r.attr_revision); h.feed(r.offline_completion_secs);
    h.feed(r.polling_short_min); h.feed(r.polling_ext_min); h.feed(r.polling_conv_min);
    h.feed(r.cap_selftests); h.feed(r.cap_conveyance); h.feed(r.cap_selective);
    h.feed(r.cap_error_logging); h.feed(r.cap_gp_logging);
    h.feed(r.sct_error_recovery); h.feed(r.sct_feature_control); h.feed(r.sct_data_table);
    h.feed(r.cap_exec_offline_immediate); h.feed(r.cap_offline_aborted_on_cmd);
    h.feed(r.cap_offline_surface_scan); h.feed(r.error_log_revision);
    h.feed(r.error_log_sectors); h.feed(r.selftest_log_revision);
    h.feed(r.selftest_log_sectors); h.feed(r.pending_defects_size);
    h.feed(r.cap_attr_autosave);
    h.feed(r.sct_hist_op_limit_min); h.feed(r.sct_hist_op_limit_max);
    h.feed(r.sct_hist_limit_min); h.feed(r.sct_hist_limit_max);
}
static void hash_row(TableHasher &h, const CacheSataHealthRow &r) {
    h.feed(r.device_index); h.feed(r.overall_status);
    h.feed(r.offline_status_value); h.feed(r.selftest_status_value);
    h.feed(r.power_cycles); h.feed(r.power_on_hours); h.feed(r.error_log_count);
    h.feed(r.pending_defects_count); h.feed(r.spare_available_pct);
    h.feed(r.spare_available_thresh_pct); h.feed(r.selftest_log_count);
    h.feed(r.selftest_log_err_total); h.feed(r.selftest_log_err_outdated);
    h.feed(r.selective_log_revision); h.feed(r.selective_flags_value);
    h.feed(r.selective_remainder_scan); h.feed(r.selective_powerup_resume_min);
    h.feed(r.logdir_gp_version); h.feed(r.logdir_smart_version);
    h.feed(r.logdir_smart_multisector); h.feed(r.error_log_revision);
    h.feed(r.cap_exec_offline_immediate); h.feed(r.cap_offline_aborted_on_cmd);
    h.feed(r.cap_offline_surface_scan); h.feed(r.cap_attr_autosave);
    h.feed(r.sct_status_format_version); h.feed(r.sct_status_sct_version);
    h.feed(r.sct_status_device_state); h.feed(r.sct_temp_power_cycle_min);
    h.feed(r.sct_temp_power_cycle_max); h.feed(r.sct_temp_lifetime_min);
    h.feed(r.sct_temp_lifetime_max); h.feed(r.sct_temp_under_limit_count);
    h.feed(r.sct_temp_over_limit_count); h.feed(r.sct_smart_status_passed);
}
static void hash_row(TableHasher &h, const CacheSataAttrRow &r) {
    h.feed(r.device_index); h.feed(r.attr_id); h.feed(r.name);
    h.feed(r.flags); h.feed(r.attr_type); h.feed(r.attr_updated);
    h.feed(r.value); h.feed(r.worst); h.feed(r.threshold);
    h.feed(r.raw_value); h.feed(r.raw_int_value); h.feed(r.raw_string); h.feed(r.status);
}
static void hash_row(TableHasher &h, const CacheSataErrorLogRow &r) {
    h.feed(r.device_index); h.feed(r.entry_index); h.feed(r.error_number);
    h.feed(r.lifetime_hours); h.feed(r.description);
    h.feed(r.comp_reg_error); h.feed(r.comp_reg_status); h.feed(r.lba);
    h.feed(r.reg_command); h.feed(r.reg_count); h.feed(r.reg_device);
    h.feed(r.reg_feature); h.feed(r.state_value);
}
static void hash_row(TableHasher &h, const CacheSataErrorCmdRow &r) {
    h.feed(r.device_index); h.feed(r.error_entry_index); h.feed(r.cmd_index);
    h.feed(r.reg_command); h.feed(r.reg_count); h.feed(r.reg_device);
    h.feed(r.reg_error); h.feed(r.reg_feature); h.feed(r.reg_lba);
    h.feed(r.reg_status); h.feed(r.timestamp_ms); h.feed(r.description);
}
static void hash_row(TableHasher &h, const CacheSataSelfTestRow &r) {
    h.feed(r.device_index); h.feed(r.entry_index); h.feed(r.type); h.feed(r.result);
    h.feed(r.passed); h.feed(r.remaining_pct); h.feed(r.lifetime_hours);
    h.feed(r.lba_first_error); h.feed(r.estimated_completion);
}
static void hash_row(TableHasher &h, const CacheSataErcRow &r) {
    h.feed(r.device_index); h.feed(r.erc_index); h.feed(r.enabled); h.feed(r.deciseconds);
}
static void hash_row(TableHasher &h, const CacheSataPhyEventRow &r) {
    h.feed(r.device_index); h.feed(r.id); h.feed(r.name);
    h.feed(r.size); h.feed(r.value); h.feed(r.overflow);
}
static void hash_row(TableHasher &h, const CacheSataSelectiveTestRow &r) {
    h.feed(r.device_index); h.feed(r.slot);
    h.feed(r.lba_min); h.feed(r.lba_max); h.feed(r.status_value); h.feed(r.status_string);
}
static void hash_row(TableHasher &h, const CacheSataPendingDefectRow &r) {
    h.feed(r.device_index); h.feed(r.entry_index); h.feed(r.lba);
}
static void hash_row(TableHasher &h, const CacheSataLogDirRow &r) {
    h.feed(r.device_index); h.feed(r.address); h.feed(r.name);
    h.feed(r.readable); h.feed(r.writable); h.feed(r.gp_sectors); h.feed(r.smart_sectors);
}
static void hash_row(TableHasher &h, const CacheSataDevStatRow &r) {
    h.feed(r.device_index); h.feed(r.page_num); h.feed(r.offset);
    h.feed(r.page_name); h.feed(r.name); h.feed(r.value);
    h.feed(r.flags_value);
}
static void hash_row(TableHasher &h, const CacheSasInfoRow &r) {
    h.feed(r.device_index); h.feed(r.vendor); h.feed(r.product); h.feed(r.revision);
    h.feed(r.compliance); h.feed(r.rotation_rate); h.feed(r.form_factor);
    h.feed(r.logical_block_size); h.feed(r.physical_block_size);
    h.feed(r.user_capacity_bytes); h.feed(r.power_cycles); h.feed(r.power_on_hours);
}
static void hash_row(TableHasher &h, const CacheSasHealthRow &r) {
    h.feed(r.device_index); h.feed(r.overall_status); h.feed(r.grown_defect_count);
    h.feed(r.non_medium_errors); h.feed(r.info_exceptions); h.feed(r.pending_defects);
}
static void hash_row(TableHasher &h, const CacheSasErrorCounterRow &r) {
    h.feed(r.device_index); h.feed(r.direction); h.feed(r.ecc_delayed);
    h.feed(r.ecc_fast); h.feed(r.rereads_rewrites); h.feed(r.total_corrected);
    h.feed(r.algorithm_invoked); h.feed(r.bytes_processed); h.feed(r.uncorrected);
}
static void hash_row(TableHasher &h, const CacheSasSelfTestRow &r) {
    h.feed(r.device_index); h.feed(r.entry_index); h.feed(r.type); h.feed(r.result);
    h.feed(r.result_str); h.feed(r.passed); h.feed(r.power_on_hours); h.feed(r.lba_first_error);
}
static void hash_row(TableHasher &h, const CacheSasBgScanRow &r) {
    h.feed(r.device_index); h.feed(r.status_value); h.feed(r.status_string);
    h.feed(r.progress_percent); h.feed(r.scans_performed); h.feed(r.medium_scans);
    h.feed(r.scan_results); h.feed(r.estimated_completion);
}
// timestamp and update_rate excluded: set to daemon's current time, not JSON data.
static void hash_row(TableHasher &h, const CacheSensorRow &r) {
    h.feed(r.device_index); h.feed(r.sensor_index); h.feed(r.type);
    h.feed(r.name); h.feed(r.source); h.feed(r.scale); h.feed(r.precision);
    h.feed(r.value); h.feed(r.oper_status); h.feed(r.units_display);
    h.feed(r.has_high_critical); h.feed(r.high_critical);
    h.feed(r.has_high_warning);  h.feed(r.high_warning);
    h.feed(r.has_low_warning);   h.feed(r.low_warning);
    h.feed(r.has_low_critical);  h.feed(r.low_critical);
}

// sort_key — natural primary key per row type, used to produce a stable
// hash regardless of which device was most recently re-parsed (clear +
// re-append shifts rows to the end, so raw iteration order is not stable).
static auto sort_key(const CacheDeviceRow &r)            { return std::make_tuple(r.index); }
static auto sort_key(const CacheNvmeControllerRow &r)    { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheNvmeNamespaceRow &r)     { return std::make_tuple(r.device_index, r.namespace_id); }
static auto sort_key(const CacheNvmeHealthRow &r)        { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheNvmeSelfTestRow &r)      { return std::make_tuple(r.device_index, r.entry_index); }
static auto sort_key(const CacheNvmeErrorLogRow &r)      { return std::make_tuple(r.device_index, r.entry_index); }
static auto sort_key(const CacheNvmeCapabilityRow &r)    { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheNvmePowerStateRow &r)    { return std::make_tuple(r.device_index, r.state_index); }
static auto sort_key(const CacheNvmeLbaFormatRow &r)     { return std::make_tuple(r.device_index, r.namespace_id, r.format_id); }
static auto sort_key(const CacheSataInfoRow &r)          { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheSataHealthRow &r)        { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheSataAttrRow &r)          { return std::make_tuple(r.device_index, r.attr_id); }
static auto sort_key(const CacheSataErrorLogRow &r)      { return std::make_tuple(r.device_index, r.entry_index); }
static auto sort_key(const CacheSataErrorCmdRow &r)      { return std::make_tuple(r.device_index, r.error_entry_index, r.cmd_index); }
static auto sort_key(const CacheSataSelfTestRow &r)      { return std::make_tuple(r.device_index, r.entry_index); }
static auto sort_key(const CacheSataErcRow &r)           { return std::make_tuple(r.device_index, r.erc_index); }
static auto sort_key(const CacheSataPhyEventRow &r)      { return std::make_tuple(r.device_index, r.id); }
static auto sort_key(const CacheSataSelectiveTestRow &r) { return std::make_tuple(r.device_index, r.slot); }
static auto sort_key(const CacheSataPendingDefectRow &r) { return std::make_tuple(r.device_index, r.entry_index); }
static auto sort_key(const CacheSataLogDirRow &r)        { return std::make_tuple(r.device_index, r.address); }
static auto sort_key(const CacheSataDevStatRow &r)       { return std::make_tuple(r.device_index, r.page_num, r.offset); }
static auto sort_key(const CacheSasInfoRow &r)           { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheSasHealthRow &r)         { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheSasErrorCounterRow &r)   { return std::make_tuple(r.device_index, static_cast<uint32_t>(r.direction)); }
static auto sort_key(const CacheSasSelfTestRow &r)       { return std::make_tuple(r.device_index, r.entry_index); }
static auto sort_key(const CacheSasBgScanRow &r)         { return std::make_tuple(r.device_index); }
static auto sort_key(const CacheSensorRow &r)            { return std::make_tuple(r.device_index, r.sensor_index); }

template<typename Row>
static uint64_t hash_vector(const std::vector<Row> &vec) {
    // Sort by natural key so hash is stable across re-parse reorderings.
    std::vector<size_t> idx(vec.size());
    std::iota(idx.begin(), idx.end(), 0);
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
        return sort_key(vec[a]) < sort_key(vec[b]);
    });
    TableHasher h;
    uint64_t sz = vec.size();
    h.feed(&sz, sizeof(sz));
    for (size_t i : idx) hash_row(h, vec[i]);
    return h.value();
}

template<typename Row>
static uint64_t hash_vector_for_device(const std::vector<Row> &vec, uint32_t dev_idx) {
    std::vector<size_t> idx;
    for (size_t i = 0; i < vec.size(); ++i)
        if (vec[i].device_index == dev_idx)
            idx.push_back(i);
    std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
        return sort_key(vec[a]) < sort_key(vec[b]);
    });
    TableHasher h;
    uint64_t sz = idx.size();
    h.feed(&sz, sizeof(sz));
    for (size_t i : idx) hash_row(h, vec[i]);
    return h.value();
}

// Update a ts_* field only when the table content hash changed, and persist.
static void update_table_ts(int tid, struct timespec &ts, uint64_t &prev_hash,
                             uint64_t new_hash, struct timespec now_ts) {
    if (new_hash == prev_hash) return;
    prev_hash = new_hash;
    ts        = now_ts;
    state_db_update(tid, new_hash, now_ts.tv_sec);
}

} // namespace

// ---------------------------------------------------------------------------
// PCI vendor name lookup
// ---------------------------------------------------------------------------

static std::unordered_map<uint32_t, std::string> s_pci_vendors;

static void load_pci_ids()
{
    FILE *f = fopen("/usr/share/misc/pci.ids", "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments and blank lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        // Vendor lines: no leading tab, 4 hex digits then two spaces
        if (line[0] != '\t') {
            unsigned int vid = 0;
            char name[220];
            if (sscanf(line, "%04x %219[^\n]", &vid, name) == 2)
                s_pci_vendors[vid] = name;
        }
    }
    fclose(f);
}

static const std::string& pci_vendor_name(uint32_t vid)
{
    static const std::string empty;
    if (s_pci_vendors.empty())
        load_pci_ids();
    auto it = s_pci_vendors.find(vid);
    return it != s_pci_vendors.end() ? it->second : empty;
}

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

static int         s_inotify_fd        { -1 };
static int         s_watch_wd          { -1 };
static std::string s_state_dir;
// Suppress device-discovered notifications during the startup scan.
static bool        s_initial_scan_done { false };
static std::unordered_map<std::string, uint32_t> s_file_device_index;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static bool ends_with(const std::string &s, const std::string &suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// ---------------------------------------------------------------------------
// URI helpers for smartmonDeviceUris
// ---------------------------------------------------------------------------

// Return the resolved sysfs path for a device, or empty on failure.
// NVMe controllers live under /sys/class/nvme/<name>;
// block devices (ATA, SAS) have a /sys/block/<name>/device symlink.
static std::string resolve_sysfs_device_path(const std::string &dev_name,
                                              DeviceProto proto) {
    std::string try_path = (proto == PROTO_NVME)
        ? "/sys/class/nvme/" + dev_name
        : "/sys/block/"      + dev_name + "/device";
    char resolved[PATH_MAX];
    if (realpath(try_path.c_str(), resolved) != nullptr)
        return resolved;
    return {};
}

// Resolve one level of symlink and normalise the path without requiring the
// target to exist.  This is intentional: the agent runs with PrivateDevices=yes
// so block device nodes (/dev/sda, /dev/nvme0n1, …) are absent from its /dev,
// but the by-* symlink directories are bind-mounted read-only.  We only need
// the path string to compare against dev_path — not the device itself.
static std::string readlink_normalized(const std::string &link_path) {
    char buf[PATH_MAX];
    ssize_t len = readlink(link_path.c_str(), buf, sizeof(buf) - 1);
    if (len < 0) return {};
    buf[len] = '\0';

    std::string target(buf);
    if (target[0] != '/') {
        // Relative — resolve against the directory containing the symlink
        size_t slash = link_path.rfind('/');
        std::string dir = (slash != std::string::npos)
                          ? link_path.substr(0, slash) : ".";
        target = dir + "/" + target;
    }

    // Collapse . and .. components
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < target.size()) {
        size_t end = target.find('/', pos);
        if (end == std::string::npos) end = target.size();
        std::string seg = target.substr(pos, end - pos);
        if (seg == "..") {
            if (!parts.empty()) parts.pop_back();
        } else if (!seg.empty() && seg != ".") {
            parts.push_back(seg);
        }
        pos = end + 1;
    }
    std::string out = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += '/';
        out += parts[i];
    }
    return out;
}

// Scan /dev/disk/by-id and /dev/disk/by-path; return space-separated
// file:// URIs for every symlink whose resolved target matches dev_path.
// For NVMe controllers (/dev/nvme0) also match namespace block devices
// (/dev/nvme0n<N>) because disk/by-* links point to the namespace.
static std::string collect_by_disk_uris(const std::string &dev_path,
                                         DeviceProto proto) {
    static const char *by_dirs[] = {
        "/dev/disk/by-id",
        "/dev/disk/by-path",
        nullptr
    };
    std::string result;
    for (int i = 0; by_dirs[i]; ++i) {
        DIR *d = opendir(by_dirs[i]);
        if (!d) {
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "uris: opendir(%s): %s",
                       by_dirs[i], strerror(errno));
            continue;
        }
        struct dirent *ent;
        while ((ent = readdir(d)) != nullptr) {
            if (ent->d_name[0] == '.') continue;
            std::string link = std::string(by_dirs[i]) + "/" + ent->d_name;
            std::string t = readlink_normalized(link);
            if (t.empty()) continue;
            bool match = (t == dev_path);
            if (!match && proto == PROTO_NVME) {
                // Match namespace block devices (nvme0n1, nvme0n2, …) but
                // NOT partitions (nvme0n1p1, nvme0n1p2, …).
                // Expected tail after dev_path: 'n' followed by one or more
                // digits and nothing else.
                if (t.size() > dev_path.size() &&
                    t.compare(0, dev_path.size(), dev_path) == 0) {
                    const char *tail = t.c_str() + dev_path.size();
                    if (*tail == 'n') {
                        ++tail;
                        while (std::isdigit((unsigned char)*tail)) ++tail;
                        if (*tail == '\0') match = true;
                    }
                }
            }
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "uris: %s: %s -> %s",
                       match ? "match" : "skip", link.c_str(), t.c_str());
            if (match) {
                if (!result.empty()) result += ' ';
                result += "file://" + link;
            }
        }
        closedir(d);
    }
    return result;
}

static void append_uri(std::string &uris, const std::string &path) {
    if (!uris.empty()) uris += ' ';
    uris += "file://" + path;
}

static void populate_device_uris(CacheDeviceRow &row, DeviceProto proto) {
    std::string uris;
    struct stat st;

    // Device node (e.g. /dev/sda, /dev/nvme0).  Always present by definition
    // even though it may not exist in the agent's private /dev namespace.
    append_uri(uris, row.path);

    // Stable sysfs block-device aliases — exist for block devices (ATA, SAS)
    // but not for NVMe character devices (/dev/nvme0).
    for (const char *prefix : { "/sys/block/", "/sys/class/block/" }) {
        std::string p = std::string(prefix) + row.name;
        if (lstat(p.c_str(), &st) == 0)
            append_uri(uris, p);
    }

    // Canonical sysfs hardware path (resolves controller/port symlinks)
    std::string sysfs = resolve_sysfs_device_path(row.name, proto);
    if (!sysfs.empty())
        append_uri(uris, sysfs);

    // /dev/disk/by-id and /dev/disk/by-path stable symlinks
    std::string by_uris = collect_by_disk_uris(row.path, proto);
    if (!by_uris.empty()) {
        if (!uris.empty()) uris += ' ';
        uris += by_uris;
    }

    row.uris = std::move(uris);
}

// Identify whether basename is a recognized smartd JSON state file.  The
// protocol is read from the JSON content by process_json_file; suffixes are only
// used as a cheap filter for smartd's conventional names plus generic exports.
static bool identify_state_file_proto(const std::string &basename,
                                      DeviceProto &proto) {
    // Determine type suffix and strip it
    struct { const char *suffix; DeviceProto proto; } types[] = {
        { ".ata.json",  PROTO_ATA  },
        { ".nvme.json", PROTO_NVME },
        { ".scsi.json", PROTO_SCSI },
        { ".sat.json",  PROTO_SAT  },
        { ".sas.json",  PROTO_SAS  },
        { ".json",      PROTO_UNKNOWN },
    };

    const char *type_suffix = nullptr;
    for (auto &t : types) {
        if (ends_with(basename, t.suffix)) {
            type_suffix = t.suffix;
            proto = t.proto;
            break;
        }
    }
    if (!type_suffix) {
        if (g_verbosity >= 1)
            syslog(LOG_DEBUG, "datasrc: skip '%s' (no recognized .TYPE.json suffix)",
                   basename.c_str());
        return false;
    }

    if (g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: accepted '%s' (suffix='%s')", basename.c_str(), type_suffix);
    return true;
}

// ---------------------------------------------------------------------------
// Startup validation
// ---------------------------------------------------------------------------

static bool smartd_pid_file_exists() {
    const char *candidates[] = {
        "/run/smartd.pid",
        "/var/run/smartd.pid",
    };
    for (const char *p : candidates) {
        struct stat st;
        if (stat(p, &st) == 0) return true;
    }
    return false;
}

static bool state_dir_has_json(const std::string &dir) {
    DIR *d = opendir(dir.c_str());
    if (!d) return false;
    struct dirent *ent;
    bool found = false;
    while ((ent = readdir(d)) != nullptr) {
        std::string name = ent->d_name;
        if (ends_with(name, ".json")) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

// ---------------------------------------------------------------------------
// JSON → cache: individual protocol parsers
// ---------------------------------------------------------------------------

// FNV-1a 32-bit hash used to derive a stable smartmonDeviceIndex from serial+model.
static uint32_t fnv1a32(const std::string &s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s)
        h = (h ^ c) * 16777619u;
    return h ? h : 1u;
}

static std::string format_wwn(const JVal &wwn) {
    char buf[32];
    uint64_t naa = wwn["naa"].as_uint64();
    uint64_t oui = wwn["oui"].as_uint64();
    uint64_t id  = wwn["id"].as_uint64();
    snprintf(buf, sizeof(buf), "0x%016llx",
        (unsigned long long)((naa << 60) | (oui << 36) | id));
    return buf;
}

static int health_status_from_passed(const JVal &root) {
    // SmartmonHealthStatus: 1=passed, 2=failed, 0=unknown
    const JVal &ss = root["smart_status"];
    if (ss.is_null()) return 0;
    const JVal &passed = ss["passed"];
    if (passed.is_null()) return 0;
    return passed.as_bool() ? 1 : 2;
}

static void parse_nvme(uint32_t dev_idx, const JVal &root) {
    g_cache.clear_device_data(dev_idx);

    const JVal &log = root["nvme_smart_health_information_log"];
    if (log.is_null()) {
        if (g_verbosity >= 1)
            syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: nvme_smart_health_information_log missing — no sensors or health data", dev_idx);
        return;
    }

    CacheNvmeHealthRow h;
    h.device_index          = dev_idx;
    h.overall_status        = health_status_from_passed(root);
    h.critical_warning      = static_cast<uint8_t>(log["critical_warning"].as_uint64());
    h.available_spare_pct   = static_cast<uint32_t>(log["available_spare"].as_uint64());
    h.available_spare_thresh= static_cast<uint32_t>(log["available_spare_threshold"].as_uint64());
    h.percentage_used       = static_cast<uint32_t>(log["percentage_used"].as_uint64());
    h.data_units_read       = log["data_units_read"].as_uint64();
    h.data_units_written    = log["data_units_written"].as_uint64();
    // bytes = data_units * 512 * 1000 (per NVMe spec one unit = 512000 bytes)
    h.data_bytes_read       = h.data_units_read  * 512000ULL;
    h.data_bytes_written    = h.data_units_written * 512000ULL;
    h.host_read_commands    = log["host_reads"].as_uint64();
    h.host_write_commands   = log["host_writes"].as_uint64();
    h.controller_busy_minutes = log["controller_busy_time"].as_uint64();
    h.power_cycles          = log["power_cycles"].as_uint64();
    h.power_on_hours        = log["power_on_hours"].as_uint64();
    h.unsafe_shutdowns      = log["unsafe_shutdowns"].as_uint64();
    h.media_errors          = log["media_errors"].as_uint64();
    h.error_log_entries     = log["num_err_log_entries"].as_uint64();
    h.warning_temp_minutes  = log["warning_temp_time"].as_uint64();
    h.critical_temp_minutes = log["critical_comp_time"].as_uint64();

    // Current self-test status
    const JVal &stlog = root["nvme_self_test_log"];
    if (!stlog.is_null()) {
        const JVal &cur = stlog["current_self_test"];
        if (!cur.is_null()) {
            const JVal &code = cur["code"];
            h.current_selftest_value = static_cast<uint32_t>(code["value"].as_uint64());
            h.current_selftest_str   = code["string"].as_string();
        }
    }

    g_cache.nvme_health.push_back(h);

    // Sensor rows: composite temperature, available spare, percentage used,
    // then per-sensor temperatures from temperature_sensors[]
    struct timespec now {}; clock_gettime(CLOCK_REALTIME, &now);
    {
        uint32_t sidx = 1;

        // Sensor 1: composite temperature
        const JVal &temp_val = log["temperature"];
        if (temp_val.is_null()) {
            if (g_verbosity >= 1)
                syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: sensor[1] Composite skipped (temperature field null)", dev_idx);
        } else {
            CacheSensorRow sr;
            sr.device_index  = dev_idx;
            sr.sensor_index  = sidx++;
            sr.type          = 3;   // celsius
            sr.name          = "Composite";
            sr.source        = "nvme_smart_health_information_log.temperature";
            sr.scale         = 9;   // units (10^0)
            sr.precision     = 0;
            sr.value         = static_cast<int32_t>(temp_val.as_int64());
            sr.oper_status   = 1;   // ok
            sr.units_display = "Celsius";
            sr.timestamp     = now.tv_sec;
            {
                const JVal &thr = root["nvme_composite_temperature_threshold"];
                if (!thr.is_null()) {
                    const JVal &warn = thr["warning"];
                    if (!warn.is_null()) {
                        sr.has_high_warning = true;
                        sr.high_warning     = static_cast<int32_t>(warn.as_int64());
                    }
                    const JVal &crit = thr["critical"];
                    if (!crit.is_null()) {
                        sr.has_high_critical = true;
                        sr.high_critical     = static_cast<int32_t>(crit.as_int64());
                    }
                }
            }
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: sensor[1] Composite temp=%d°C warn=%s(%d) crit=%s(%d)",
                       dev_idx, sr.value,
                       sr.has_high_warning  ? "yes" : "no", sr.high_warning,
                       sr.has_high_critical ? "yes" : "no", sr.high_critical);
            g_cache.sensors.push_back(sr);
        }

        // Sensor 2: available spare % (low_critical = spare threshold,
        // low_warning = 100% higher than critical)
        {
            CacheSensorRow sr;
            sr.device_index    = dev_idx;
            sr.sensor_index    = sidx++;
            sr.type            = 10;  // percent
            sr.name            = "Available Spare";
            sr.source          = "nvme_smart_health_information_log.available_spare";
            sr.scale           = 9;
            sr.precision       = 0;
            sr.value           = static_cast<int32_t>(h.available_spare_pct);
            sr.oper_status     = 1;
            sr.units_display   = "percent";
            sr.timestamp       = now.tv_sec;
            sr.has_low_critical = true;
            sr.low_critical     = static_cast<int32_t>(h.available_spare_thresh);
            sr.has_low_warning  = true;
            sr.low_warning      = sr.low_critical * 2;
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: sensor[2] AvailableSpare value=%d%% low_warn=%d%% low_crit=%d%%",
                       dev_idx, sr.value, sr.low_warning, sr.low_critical);
            g_cache.sensors.push_back(sr);
        }

        // Sensor 3: percentage used
        {
            CacheSensorRow sr;
            sr.device_index  = dev_idx;
            sr.sensor_index  = sidx++;
            sr.type          = 10;  // percent
            sr.name          = "Percentage Used";
            sr.source        = "nvme_smart_health_information_log.percentage_used";
            sr.scale         = 9;
            sr.precision     = 0;
            sr.value         = static_cast<int32_t>(h.percentage_used);
            sr.oper_status   = 1;
            sr.units_display = "percent";
            sr.timestamp     = now.tv_sec;
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: sensor[3] PercentageUsed value=%d%%",
                       dev_idx, sr.value);
            g_cache.sensors.push_back(sr);
        }

        // Sensors 10+: individual temperature sensors
        // NVMe spec provides no per-sensor thresholds; apply the composite threshold to all
        const JVal &tsensors = log["temperature_sensors"];
        if (!tsensors.is_array()) {
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: temperature_sensors not present (no per-sensor rows)", dev_idx);
        } else {
            const JVal &thr = root["nvme_composite_temperature_threshold"];
            for (std::size_t i = 0; i < tsensors.size(); ++i) {
                const JVal &tv = tsensors[i];
                if (tv.is_null()) continue;
                CacheSensorRow sr;
                sr.device_index  = dev_idx;
                sr.sensor_index  = static_cast<uint32_t>(10 + i);
                sr.type          = 3;   // celsius
                char nbuf[32];
                snprintf(nbuf, sizeof(nbuf), "Sensor %zu", i + 1);
                sr.name          = nbuf;
                sr.source        = "nvme_smart_health_information_log.temperature_sensors";
                sr.scale         = 9;
                sr.precision     = 0;
                sr.value         = static_cast<int32_t>(tv.as_int64());
                sr.oper_status   = 1;
                sr.units_display = "Celsius";
                sr.timestamp     = now.tv_sec;
                if (!thr.is_null()) {
                    const JVal &warn = thr["warning"];
                    if (!warn.is_null()) {
                        sr.has_high_warning = true;
                        sr.high_warning     = static_cast<int32_t>(warn.as_int64());
                    }
                    const JVal &crit = thr["critical"];
                    if (!crit.is_null()) {
                        sr.has_high_critical = true;
                        sr.high_critical     = static_cast<int32_t>(crit.as_int64());
                    }
                }
                if (g_verbosity >= 2)
                    syslog(LOG_DEBUG, "datasrc: NVMe dev_idx=%u: sensor[%zu] '%s' temp=%d°C",
                           dev_idx, 10 + i, sr.name.c_str(), sr.value);
                g_cache.sensors.push_back(sr);
            }
        }
    }

    // Controller info
    {
        CacheNvmeControllerRow ctrl;
        ctrl.device_index      = dev_idx;
        const JVal &pci = root["nvme_pci_vendor"];
        ctrl.pci_vendor_id     = pci.is_null() ? 0 : static_cast<uint32_t>(pci["id"].as_uint64());
        ctrl.pci_subsystem_id  = pci.is_null() ? 0 : static_cast<uint32_t>(pci["subsystem_id"].as_uint64());
        ctrl.pci_vendor_id_text       = pci_vendor_name(ctrl.pci_vendor_id);
        ctrl.pci_subsystem_vendor_text    = pci_vendor_name(ctrl.pci_subsystem_id);
        ctrl.ieee_oui          = static_cast<uint32_t>(root["nvme_ieee_oui_identifier"].as_uint64());
        ctrl.total_capacity    = root["nvme_total_capacity"].as_uint64();
        ctrl.unallocated_capacity = root["nvme_unallocated_capacity"].as_uint64();
        ctrl.controller_id     = static_cast<uint32_t>(root["nvme_controller_id"].as_uint64());
        const JVal &ver = root["nvme_version"];
        if (!ver.is_null()) {
            ctrl.version_string = ver["string"].as_string();
            ctrl.version_value  = static_cast<uint32_t>(ver["value"].as_uint64());
        }
        ctrl.namespace_count   = static_cast<uint32_t>(root["nvme_number_of_namespaces"].as_uint64());
        ctrl.max_data_transfer_pages = static_cast<uint32_t>(root["nvme_maximum_data_transfer_pages"].as_uint64());
        if (ctrl.controller_id != 0 || ctrl.pci_vendor_id != 0)
            g_cache.nvme_controllers.push_back(ctrl);
    }

    // Capability table (1 row per controller)
    {
        const JVal &fw  = root["nvme_firmware_update_capabilities"];
        const JVal &adm = root["nvme_optional_admin_commands"];
        const JVal &nvm = root["nvme_optional_nvm_commands"];
        const JVal &lpa = root["nvme_log_page_attributes"];

        CacheNvmeCapabilityRow cap;
        cap.device_index = dev_idx;
        if (!fw.is_null()) {
            cap.firmware_update_raw     = static_cast<uint32_t>(fw["value"].as_uint64());
            cap.firmware_slot_count     = static_cast<uint32_t>(fw["slots"].as_uint64());
            // activiation_without_reset=true means NO reset required
            cap.firmware_reset_required = !fw["activation_without_reset"].as_bool();
        }
        if (!adm.is_null()) {
            cap.optional_admin_cmd_raw  = static_cast<uint32_t>(adm["value"].as_uint64());
            std::string t;
            struct { const char *key; const char *label; } adm_bits[] = {
                {"security_send_receive",      "Security Send/Receive"},
                {"format_nvm",                 "Format NVM"},
                {"firmware_download",          "Firmware Download"},
                {"namespace_management",       "Namespace Management"},
                {"self_test",                  "Self-test"},
                {"directives",                 "Directives"},
                {"mi_send_receive",            "MI Send/Receive"},
                {"virtualization_management",  "Virtualization Management"},
                {"doorbell_buffer_config",     "Doorbell Buffer Config"},
                {"get_lba_status",             "Get LBA Status"},
                {"command_and_feature_lockdown","Command and Feature Lockdown"},
            };
            for (auto &b : adm_bits)
                if (adm[b.key].as_bool()) { if (!t.empty()) t += ", "; t += b.label; }
            cap.optional_admin_cmd_text = t;
        }
        if (!nvm.is_null()) {
            cap.optional_nvm_cmd_raw    = static_cast<uint32_t>(nvm["value"].as_uint64());
            std::string t;
            struct { const char *key; const char *label; } nvm_bits[] = {
                {"compare",                        "Compare"},
                {"write_uncorrectable",            "Write Uncorrectable"},
                {"dataset_management",             "Dataset Management"},
                {"write_zeroes",                   "Write Zeroes"},
                {"save_select_feature_nonzero",    "Save/Select Feature Nonzero"},
                {"reservations",                   "Reservations"},
                {"timestamp",                      "Timestamp"},
                {"verify",                         "Verify"},
                {"copy",                           "Copy"},
            };
            for (auto &b : nvm_bits)
                if (nvm[b.key].as_bool()) { if (!t.empty()) t += ", "; t += b.label; }
            cap.optional_nvm_cmd_text = t;
        }
        if (!lpa.is_null()) {
            cap.log_page_attr_raw       = static_cast<uint32_t>(lpa["value"].as_uint64());
            std::string t;
            struct { const char *key; const char *label; } lpa_bits[] = {
                {"smart_health_per_namespace",  "SMART/Health per Namespace"},
                {"commands_effects_log",        "Commands Effects Log"},
                {"extended_get_log_page_cmd",   "Extended Get Log Page"},
                {"telemetry_log",               "Telemetry Log"},
                {"persistent_event_log",        "Persistent Event Log"},
                {"supported_log_pages_log",     "Supported Log Pages Log"},
                {"telemetry_data_area_4",       "Telemetry Data Area 4"},
            };
            for (auto &b : lpa_bits)
                if (lpa[b.key].as_bool()) { if (!t.empty()) t += ", "; t += b.label; }
            cap.log_page_attr_text = t;
        }
        g_cache.nvme_capabilities.push_back(cap);
    }

    // Power state table
    {
        const JVal &ps_arr = root["nvme_power_states"];
        if (ps_arr.is_array()) {
            for (std::size_t i = 0; i < ps_arr.size(); ++i) {
                const JVal &ps = ps_arr[i];
                CacheNvmePowerStateRow r;
                r.device_index          = dev_idx;
                r.state_index           = static_cast<uint32_t>(i);
                r.operational           = !ps["non_operational_state"].as_bool();
                r.read_latency_rank     = static_cast<uint32_t>(ps["relative_read_latency"].as_uint64());
                r.read_throughput_rank  = static_cast<uint32_t>(ps["relative_read_throughput"].as_uint64());
                r.write_latency_rank    = static_cast<uint32_t>(ps["relative_write_latency"].as_uint64());
                r.write_throughput_rank = static_cast<uint32_t>(ps["relative_write_throughput"].as_uint64());
                r.entry_latency_usec    = static_cast<uint32_t>(ps["entry_latency_us"].as_uint64());
                r.exit_latency_usec     = static_cast<uint32_t>(ps["exit_latency_us"].as_uint64());
                const JVal &mp = ps["max_power"];
                if (!mp.is_null()) {
                    uint64_t upw = mp["units_per_watt"].as_uint64();
                    if (upw > 0)
                        r.max_power_mw = static_cast<uint32_t>(mp["value"].as_uint64() * 1000 / upw);
                }
                // active_power and idle_power are optional NVMe fields
                const JVal &ap = ps["active_power"];
                if (!ap.is_null()) {
                    r.has_active_power = true;
                    uint64_t upw = ap["units_per_watt"].as_uint64();
                    r.active_power_mw = (upw > 0)
                        ? static_cast<uint32_t>(ap["value"].as_uint64() * 1000 / upw) : 0;
                }
                const JVal &ip = ps["idle_power"];
                if (!ip.is_null()) {
                    r.has_idle_power = true;
                    uint64_t upw = ip["units_per_watt"].as_uint64();
                    r.idle_power_mw = (upw > 0)
                        ? static_cast<uint32_t>(ip["value"].as_uint64() * 1000 / upw) : 0;
                }
                g_cache.nvme_power_states.push_back(r);
            }
        }
    }

    // LBA format table (per namespace, per format)
    {
        const JVal &ns_arr = root["nvme_namespaces"];
        if (ns_arr.is_array()) {
            for (std::size_t i = 0; i < ns_arr.size(); ++i) {
                const JVal &ns = ns_arr[i];
                uint32_t nsid = static_cast<uint32_t>(ns["id"].as_uint64());
                const JVal &fmts = ns["lba_formats"];
                if (fmts.is_array()) {
                    for (std::size_t j = 0; j < fmts.size(); ++j) {
                        const JVal &f = fmts[j];
                        CacheNvmeLbaFormatRow r;
                        r.device_index  = dev_idx;
                        r.namespace_id  = nsid;
                        r.format_id     = static_cast<uint32_t>(j);
                        r.current       = f["formatted"].as_bool();
                        r.data_size     = static_cast<uint32_t>(f["data_bytes"].as_uint64());
                        r.metadata_size = static_cast<uint32_t>(f["metadata_bytes"].as_uint64());
                        r.rel_perf      = static_cast<uint32_t>(f["relative_performance"].as_uint64());
                        g_cache.nvme_lba_formats.push_back(r);
                    }
                }
            }
        }
    }

    // Namespace table
    {
        const JVal &ns_arr = root["nvme_namespaces"];
        if (ns_arr.is_array()) {
            for (std::size_t i = 0; i < ns_arr.size(); ++i) {
                const JVal &ns = ns_arr[i];
                CacheNvmeNamespaceRow r;
                r.device_index      = dev_idx;
                r.namespace_id      = static_cast<uint32_t>(ns["id"].as_uint64());
                r.size_bytes        = ns["size"]["bytes"].as_uint64();
                r.capacity_bytes    = ns["capacity"]["bytes"].as_uint64();
                r.utilization_bytes = ns["utilization"]["bytes"].as_uint64();
                r.formatted_lba_size= static_cast<uint32_t>(ns["formatted_lba_size"].as_uint64());
                r.size_blocks       = ns["size"]["blocks"].as_uint64();
                r.capacity_blocks   = ns["capacity"]["blocks"].as_uint64();
                r.utilization_blocks= ns["utilization"]["blocks"].as_uint64();
                g_cache.nvme_namespaces.push_back(r);
            }
        }
    }

    // Error log
    {
        const JVal &errlog = root["nvme_error_information_log"];
        if (!errlog.is_null()) {
            const JVal &tbl = errlog["table"];
            if (tbl.is_array()) {
                for (std::size_t i = 0; i < tbl.size(); ++i) {
                    const JVal &e = tbl[i];
                    CacheNvmeErrorLogRow r;
                    r.device_index  = dev_idx;
                    r.entry_index   = static_cast<uint32_t>(i + 1);
                    r.error_count   = e["error_count"].as_uint64();
                    r.sqid          = static_cast<uint32_t>(e["submission_queue_id"].as_uint64());
                    r.command_id    = static_cast<uint32_t>(e["command_id"].as_uint64());
                    const JVal &sf  = e["status_field"];
                    r.status_field  = static_cast<uint32_t>(sf["value"].as_uint64());
                    r.status_code   = static_cast<uint32_t>(sf["status_code"].as_uint64());
                    r.status_code_type = static_cast<uint32_t>(sf["status_code_type"].as_uint64());
                    r.do_not_retry  = sf["do_not_retry"].as_bool();
                    r.phase_tag     = sf["phase_tag"].as_bool();
                    r.status_string = sf["string"].as_string();
                    r.lba           = e["lba"]["value"].as_uint64();
                    r.nsid          = static_cast<uint32_t>(e["nsid"].as_uint64());
                    r.parm_error_location = static_cast<uint32_t>(e["parameter_error_location"].as_uint64());
                    r.error_timestamp = now.tv_sec;
                    g_cache.nvme_error_log.push_back(r);
                }
            }
        }
    }

    // Self-test log entries
    if (!stlog.is_null()) {
        const JVal &table = stlog["table"];
        if (table.is_array()) {
            for (std::size_t i = 0; i < table.size(); ++i) {
                const JVal &e = table[i];
                CacheNvmeSelfTestRow r;
                r.device_index  = dev_idx;
                r.entry_index   = static_cast<uint32_t>(i + 1);
                r.number        = static_cast<uint32_t>(i + 1);
                r.type          = static_cast<int>(e["self_test_code"]["value"].as_int64());
                r.result        = static_cast<int>(e["self_test_result"]["value"].as_int64());
                r.result_text   = e["self_test_result"]["string"].as_string();
                r.power_on_hours= e["power_on_hours"].as_uint64();
                const JVal &flba= e["failing_lba"];
                // 0xFFFFFFFFFFFFFFFF means no error
                r.failing_lba   = flba.is_null() ? 0 : flba.as_uint64();
                r.namespace_id  = static_cast<uint32_t>(e["nsid"].as_uint64());
                r.segment_number= static_cast<uint32_t>(e["segment_number"].as_uint64());
                r.status_code_type = static_cast<uint32_t>(e["status_code_type"].as_uint64());
                r.status_code   = static_cast<uint32_t>(e["status_code"].as_uint64());
                g_cache.nvme_selftests.push_back(r);
            }
        }
    }

    // Update last-change timestamps only when content hash changed
    auto &hv = g_cache.table_hashes;
    update_table_ts(TABLE_DEVICE,        g_cache.ts_device_table,    hv[TABLE_DEVICE],        hash_vector(g_cache.devices),           now);
    update_table_ts(TABLE_NVME_CTRL,     g_cache.ts_nvme_controller, hv[TABLE_NVME_CTRL],     hash_vector(g_cache.nvme_controllers),  now);
    update_table_ts(TABLE_NVME_NS,       g_cache.ts_nvme_namespace,  hv[TABLE_NVME_NS],       hash_vector(g_cache.nvme_namespaces),   now);
    update_table_ts(TABLE_NVME_HEALTH,   g_cache.ts_nvme_health,     hv[TABLE_NVME_HEALTH],   hash_vector(g_cache.nvme_health),       now);
    update_table_ts(TABLE_NVME_SELFTEST, g_cache.ts_nvme_selftest,   hv[TABLE_NVME_SELFTEST], hash_vector(g_cache.nvme_selftests),    now);
    update_table_ts(TABLE_NVME_ERRLOG,   g_cache.ts_nvme_error_log,  hv[TABLE_NVME_ERRLOG],   hash_vector(g_cache.nvme_error_log),    now);
    update_table_ts(TABLE_NVME_CAP,      g_cache.ts_nvme_capability, hv[TABLE_NVME_CAP],      hash_vector(g_cache.nvme_capabilities), now);
    update_table_ts(TABLE_NVME_PS,       g_cache.ts_nvme_power_state,hv[TABLE_NVME_PS],       hash_vector(g_cache.nvme_power_states), now);
    update_table_ts(TABLE_NVME_LBA,      g_cache.ts_nvme_lba_format, hv[TABLE_NVME_LBA],      hash_vector(g_cache.nvme_lba_formats),  now);
    update_table_ts(TABLE_SENSOR,        g_cache.ts_sensor,          hv[TABLE_SENSOR],        hash_vector(g_cache.sensors),           now);
}

static void parse_seagate_farm(uint32_t dev_idx, const JVal &farm) {
    // Timestamp from FARM log itself; fall back to wall clock.
    time_t farm_ts = static_cast<time_t>(farm["local_time"]["time_t"].as_int64());
    if (farm_ts == 0) farm_ts = time(nullptr);

    // Emit one CacheSataDevStatRow per numeric scalar field in each FARM page.
    // Page numbers 100-105 avoid collision with ACS ata_device_statistics pages (1-7).
    // Emit one row per scalar. For sub-objects, flatten one level:
    // name = "parent_key.child_key", preserving insertion order throughout.
    auto emit_scalar = [&](uint32_t page_num, const std::string &page_name,
                           uint32_t &offset, const std::string &name, const JVal &val) {
        CacheSataDevStatRow r;
        r.device_index = dev_idx;
        r.page_num     = page_num;
        r.offset       = offset++;
        r.page_name    = page_name;
        r.name         = name;
        r.value        = static_cast<uint64_t>(val.as_int64());
        r.flags_value  = 0;
        g_cache.sata_dev_stats.push_back(r);
    };

    auto emit_page = [&](const JVal &page_obj, uint32_t page_num,
                         const std::string &page_name) {
        if (!page_obj.is_object()) return;
        std::vector<std::pair<std::size_t, std::string>> sorted_keys;
        sorted_keys.reserve(page_obj.obj_keys.size());
        for (const auto &kv : page_obj.obj_keys)
            sorted_keys.push_back({kv.second, kv.first});
        std::sort(sorted_keys.begin(), sorted_keys.end());
        uint32_t offset = 1;
        for (const auto &kv2 : sorted_keys) {
            const JVal &val = page_obj.arr[kv2.first];
            const std::string &key = kv2.second;
            if (val.is_number()) {
                emit_scalar(page_num, page_name, offset, key, val);
            } else if (val.is_object()) {
                // Flatten sub-object: name = "parent_key.child_key"
                std::vector<std::pair<std::size_t, std::string>> sub_keys;
                sub_keys.reserve(val.obj_keys.size());
                for (const auto &skv : val.obj_keys)
                    sub_keys.push_back({skv.second, skv.first});
                std::sort(sub_keys.begin(), sub_keys.end());
                for (const auto &skv2 : sub_keys) {
                    const JVal &sv = val.arr[skv2.first];
                    if (!sv.is_number()) continue;
                    const std::string &child = skv2.second;
                    // Strip longest common _-word prefix shared with parent key
                    size_t sep = 0;
                    for (size_t i = 0; i < key.size() && i < child.size() && key[i] == child[i]; ++i)
                        if (child[i] == '_') sep = i + 1;
                    std::string child_short = (sep > 0) ? child.substr(sep) : child;
                    emit_scalar(page_num, page_name, offset, key + "." + child_short, sv);
                }
            }
            // arrays and strings are skipped
        }
    };

    emit_page(farm["page_0_log_header"],             100, "FARM Log Header");
    emit_page(farm["page_1_drive_information"],      101, "FARM Drive Information");
    emit_page(farm["page_2_workload_statistics"],    102, "FARM Workload Statistics");
    emit_page(farm["page_3_error_statistics"],       103, "FARM Error Statistics");
    emit_page(farm["page_4_environment_statistics"], 104, "FARM Environment Statistics");
    emit_page(farm["page_5_reliability_statistics"], 105, "FARM Reliability Statistics");

    // Sensor rows from page 4: 12V supply, 5V supply, humidity, motor power.
    // No threshold limits (not present in FARM log).
    const JVal &env = farm["page_4_environment_statistics"];
    if (env.is_object()) {
        struct FarmSensor {
            uint32_t    sensor_index;
            const char *field;
            const char *name;
            int         type;   // SmartmonSensorDataType
            int         scale;  // SmartmonSensorDataScale
            const char *units_display;
        };
        static const FarmSensor farm_sensors[] = {
            { 3, "current_12v_in_mv",    "12V Supply",  6, 8, "mV"     },
            { 4, "current_5v_in_mv",     "5V Supply",   6, 8, "mV"     },
            { 5, "humidity",             "Humidity",   10, 9, "percent" },
            { 6, "current_motor_power",  "Motor Power", 4, 8, "mW"     },
        };
        for (const auto &fs : farm_sensors) {
            const JVal &v = env[fs.field];
            if (v.is_null()) continue;
            CacheSensorRow sr;
            sr.device_index  = dev_idx;
            sr.sensor_index  = fs.sensor_index;
            sr.type          = fs.type;
            sr.name          = fs.name;
            sr.source        = std::string("seagate_farm_log.page_4_environment_statistics.") + fs.field;
            sr.scale         = fs.scale;
            sr.precision     = 0;
            sr.value         = static_cast<int32_t>(v.as_int64());
            sr.oper_status   = 1;
            sr.units_display = fs.units_display;
            sr.timestamp     = farm_ts;
            g_cache.sensors.push_back(sr);
        }
    }
}

static void parse_ata(uint32_t dev_idx, const JVal &root) {
    g_cache.clear_device_data(dev_idx);

    const JVal &attrs = root["ata_smart_attributes"]["table"];
    if (!attrs.is_array() && g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: ATA dev_idx=%u: ata_smart_attributes.table missing or not array", dev_idx);
    if (attrs.is_array()) {
        for (std::size_t i = 0; i < attrs.size(); ++i) {
            const JVal &a = attrs[i];
            CacheSataAttrRow r;
            r.device_index = dev_idx;
            r.attr_id      = static_cast<uint32_t>(a["id"].as_uint64());
            r.name         = a["name"].as_string();
            r.value        = static_cast<uint32_t>(a["value"].as_uint64());
            r.worst        = static_cast<uint32_t>(a["worst"].as_uint64());
            r.threshold    = static_cast<uint32_t>(a["thresh"].as_uint64());
            r.raw_string     = a["raw"]["string"].as_string();
            r.raw_int_value  = a["raw"]["value"].as_int64();
            // Parse the leading decimal from raw_string (matches smartctl display).
            // raw.value is the full 6-byte vendor-encoded integer which packs
            // extra fields (e.g. sub-minute counters, min/max temps) into the
            // upper bytes — not what a monitoring system wants.
            {
                const char *s = r.raw_string.c_str();
                char *endp;
                unsigned long long v = strtoull(s, &endp, 10);
                r.raw_value = (endp > s)
                    ? static_cast<int64_t>(v)
                    : r.raw_int_value;
            }

            const JVal &flags = a["flags"];
            r.flags        = static_cast<uint8_t>(flags["value"].as_uint64());
            // attr_type: 1=prefail, 2=old-age
            r.attr_type    = flags["prefailure"].as_bool() ? 1 : 2;
            // attr_updated: 1=always, 2=offline
            r.attr_updated = flags["updated_online"].as_bool() ? 1 : 2;

            // SmartmonAtaSmartAttrStatus derived from when_failed field
            // notRelevant(-1), unknown(0), ok(1), failingNow(2), failedInPast(3)
            {
                std::string wf = a["when_failed"].as_string();
                if (r.threshold == 0)
                    r.status = -1;
                else if (wf == "now")
                    r.status = 2;
                else if (wf == "past")
                    r.status = 3;
                else
                    r.status = 1;
            }

            g_cache.sata_attrs.push_back(r);
        }

        // Temperature sensor: prefer attr 194, fall back to attr 190
        const CacheSataAttrRow *temp_attr = nullptr;
        for (const auto &a : g_cache.sata_attrs) {
            if (a.device_index != dev_idx) continue;
            if (a.attr_id == 194) { temp_attr = &a; break; }
            if (a.attr_id == 190 && !temp_attr) temp_attr = &a;
        }
        if (!temp_attr) {
            if (g_verbosity >= 1)
                syslog(LOG_DEBUG, "datasrc: ATA dev_idx=%u: no temp attr (id 190/194) — sensor table will be empty for this device", dev_idx);
        } else {
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: ATA dev_idx=%u: using attr id=%u raw_value=%lld for temperature sensor",
                       dev_idx, temp_attr->attr_id, (long long)temp_attr->raw_value);
        }
        if (temp_attr) {
            CacheSensorRow sr;
            sr.device_index  = dev_idx;
            sr.sensor_index  = 1;
            sr.type          = 3;   // celsius
            sr.name          = "Temperature";
            sr.source        = (temp_attr->attr_id == 194)
                               ? "ata_smart_attributes.table[id=194].raw"
                               : "ata_smart_attributes.table[id=190].raw";
            sr.scale         = 9;   // units
            sr.precision     = 0;
            sr.value         = static_cast<int32_t>(temp_attr->raw_value);
            sr.oper_status   = 1;
            sr.units_display = "Celsius";
            sr.timestamp     = time(nullptr);
            {
                uint32_t rrate = static_cast<uint32_t>(root["rotation_rate"].as_uint64());
                bool is_hdd = (rrate > 1); // rotation_rate >1 means actual RPM; 0/1 = SSD/non-rotating.
                if (is_hdd) {
                    // Harddisk drive
                    sr.has_high_warning  = true;  sr.high_warning  = 45;
                    sr.has_high_critical = true;  sr.high_critical = 60;
                    sr.has_low_warning   = true;  sr.low_warning   = 5;
                    sr.has_low_critical  = true;  sr.low_critical  = 1;
                } else {
                    // Solidstate drive
                    sr.has_high_warning  = true;  sr.high_warning  = 60;
                    sr.has_high_critical = true;  sr.high_critical = 70;
                    sr.has_low_warning   = true;  sr.low_warning   = 5;
                    sr.has_low_critical  = true;  sr.low_critical  = 1;
                }

                const JVal &tmp = root["temperature"];
                bool got_max = false, got_min = false;
                if (!tmp.is_null()) {
                    const JVal &op_max = tmp["op_limit_max"];
                    if (!op_max.is_null()) {
                        sr.has_high_critical = true;
                        sr.high_critical     = static_cast<int32_t>(op_max.as_int64());
                        got_max = true;
                    }
                    const JVal &op_min = tmp["op_limit_min"];
                    if (!op_min.is_null()) {
                        sr.has_low_critical = true;
                        sr.low_critical     = static_cast<int32_t>(op_min.as_int64());
                        got_min = true;
                    }
                }

                if (g_verbosity >= 2)
                    syslog(LOG_DEBUG, "datasrc: ATA dev_idx=%u: %s thresholds hi_warn=%d hi_crit=%d low_warn=%d low_crit=%d (op_limit_max=%s op_limit_min=%s)",
                           dev_idx, is_hdd ? "HDD" : "SSD", sr.high_warning, sr.high_critical,
                           sr.low_warning, sr.low_critical, got_max ? "yes" : "no", got_min ? "yes" : "no");
            }
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: ATA dev_idx=%u: sensor[1] Temperature value=%d°C → pushed to cache (total sensors=%zu)",
                       dev_idx, sr.value, g_cache.sensors.size() + 1);
            g_cache.sensors.push_back(sr);
        }
    }

    // Sensor 2 (redundant — attr 194/190 already covers temperature.current; kept for sensor MIB reference):
    // source: temperature.current, high_critical=op_limit_max, low_critical=op_limit_min
    // (fallback to current if a limit is absent)
    //
    // {
    //     const JVal &tmp = root["temperature"];
    //     if (!tmp.is_null() && !tmp["current"].is_null()) {
    //         time_t now = time(nullptr);
    //         CacheSensorRow sr;
    //         sr.device_index  = dev_idx;
    //         sr.sensor_index  = 2;
    //         sr.type          = 3;   // celsius
    //         sr.name          = "Temperature";
    //         sr.source        = "temperature.current";
    //         sr.scale         = 9;
    //         sr.precision     = 0;
    //         sr.value         = static_cast<int32_t>(tmp["current"].as_int64());
    //         sr.oper_status   = 1;
    //         sr.units_display = "Celsius";
    //         sr.timestamp     = now;
    //         int32_t cur = sr.value;
    //         const JVal &hi = tmp["op_limit_max"];
    //         sr.has_high_critical = true;
    //         sr.high_critical     = hi.is_null() ? cur : static_cast<int32_t>(hi.as_int64());
    //         const JVal &lo = tmp["op_limit_min"];
    //         sr.has_low_critical  = true;
    //         sr.low_critical      = lo.is_null() ? cur : static_cast<int32_t>(lo.as_int64());
    //         g_cache.sensors.push_back(sr);
    //     }
    // }

    // Sensor 2: spare_available.current_percent
    // This is Guessed from the normalized value of certain SMART attributes matching the regex at src/ataprint.cpp:1199-1202:
    // Reallocated_Sector_C.*|Retired_Block_C.*|(Remain.*_)?Spare_Blocks(_(Avail|Remain).*)?
    // Specifically attributes ID 5, 17, or ≥100 with matching names. The value at ataprint.cpp:1204 is: 
    //
    // (low_critical = threshold_percent, low_warning = 100% higher than critical)
    {
        const JVal &spare = root["spare_available"];
        if (!spare.is_null() && !spare["current_percent"].is_null()) {
            time_t now = time(nullptr);
            CacheSensorRow sr;
            sr.device_index    = dev_idx;
            sr.sensor_index    = 2;
            sr.type            = 10;  // percent
            sr.name            = "wear indicator";
            sr.source          = "spare_available.current_percent";
            sr.scale           = 9;
            sr.precision       = 0;
            sr.value           = static_cast<int32_t>(spare["current_percent"].as_uint64());
            sr.oper_status     = 1;
            sr.units_display   = "percent";
            sr.timestamp       = now;
            const JVal &thresh = spare["threshold_percent"];
            if (!thresh.is_null()) {
                sr.has_low_critical = true;
                sr.low_critical     = static_cast<int32_t>(thresh.as_uint64());
                sr.has_low_warning  = true;
                sr.low_warning      = sr.low_critical * 2;
            }
            if (g_verbosity >= 2)
                syslog(LOG_DEBUG, "datasrc: ATA dev_idx=%u: sensor[2] SpareAvailable value=%d%% lo_warn=%s(%d) lo_crit=%s(%d)",
                       dev_idx, sr.value,
                       sr.has_low_warning ? "yes" : "no", sr.low_warning,
                       sr.has_low_critical ? "yes" : "no", sr.low_critical);
            g_cache.sensors.push_back(sr);
        }
    }

    // Self-test log — smartctl -x reports extended log; fall back to standard
    const JVal &stlog_ext = root["ata_smart_self_test_log"]["extended"]["table"];
    const JVal &stlog_std = root["ata_smart_self_test_log"]["standard"]["table"];
    const JVal &stlog = stlog_ext.is_array() ? stlog_ext : stlog_std;
    if (stlog.is_array()) {
        for (std::size_t i = 0; i < stlog.size(); ++i) {
            const JVal &e = stlog[i];
            CacheSataSelfTestRow r;
            r.device_index   = dev_idx;
            r.entry_index    = static_cast<uint32_t>(i + 1);
            r.type           = static_cast<int>(e["type"]["value"].as_int64());
            // SmartmonAtaSelfTestResult: completedWithoutError(1) = raw 0,
            // raw nibble 0-8 → TC value 1-9; raw 15 (in-progress) → TC 15.
            {
                int raw = static_cast<int>(e["status"]["value"].as_int64());
                if (raw >= 0 && raw <= 8) r.result = raw + 1;
                else if (raw == 15)       r.result = 15;  // inProgress
                else                      r.result = 0;   // unknown
            }
            r.passed         = e["status"]["passed"].as_bool();
            r.remaining_pct  = static_cast<uint32_t>(
                                  e["status"]["remaining_percent"].as_uint64());
            r.lifetime_hours = e["lifetime_hours"].as_uint64();
            const JVal &lba  = e["lba_of_first_error"];
            r.lba_first_error= lba.is_null() ? 0 : lba.as_uint64();
            g_cache.sata_selftests.push_back(r);
        }
    }

    // SATA info
    {
        CacheSataInfoRow info;
        info.device_index        = dev_idx;
        {
            uint32_t sv = static_cast<uint32_t>(root["sata_version"]["value"].as_uint64()) & 0x0fffu;
            int msb = -1;
            for (int b = 11; b >= 0; b--)
                if (sv & (1u << b)) { msb = b; break; }
            info.sata_version = (msb >= 11) ? 12u :
                                (msb >= 0)  ? static_cast<uint32_t>(msb + 1) : 0u;
        }
        info.rotation_rate = static_cast<uint32_t>(root["rotation_rate"].as_uint64());
        info.form_factor   = static_cast<uint32_t>(root["form_factor"]["ata_value"].as_uint64()) & 0xfu;
        info.logical_block_size  = static_cast<uint32_t>(root["logical_block_size"].as_uint64());
        info.physical_block_size = static_cast<uint32_t>(root["physical_block_size"].as_uint64());
        info.user_capacity_bytes = root["user_capacity"]["bytes"].as_uint64();
        info.in_smartctl_db      = root["in_smartctl_database"].as_bool();
        const JVal &ss = root["smart_support"];
        info.smart_available     = ss["available"].as_bool();
        info.smart_enabled       = ss["enabled"].as_bool();
        info.trim_supported      = root["trim"]["supported"].as_bool();
        info.user_capacity_blocks = root["user_capacity"]["blocks"].as_uint64();
        {
            const JVal &apm = root["ata_apm"];
            if (!apm.is_null()) {
                info.apm_enabled = apm["enabled"].as_bool();
                info.apm_level   = static_cast<uint32_t>(apm["level"].as_uint64());
                info.apm_string  = apm["string"].as_string();
            }
        }
        {
            const JVal &av = root["ata_version"];
            uint32_t maj = static_cast<uint32_t>(av["major_value"].as_uint64());
            info.ata_version_major = maj;
            info.ata_version_minor = static_cast<uint32_t>(av["minor_value"].as_uint64());
            int msb = -1;
            for (int b = 15; b >= 1; b--)
                if (maj & (1u << b)) { msb = b; break; }
            info.ata_version = (msb >= 14) ? 14u :
                               (msb >= 1)  ? static_cast<uint32_t>(msb) : 0u;
        }
        {
            const JVal &spd = root["interface_speed"];
            if (!spd.is_null()) {
                const JVal &cur = spd["current"];
                if (!cur.is_null())
                    info.if_speed_current_mbps = static_cast<uint32_t>(
                        cur["bits_per_unit"].as_uint64() * cur["units_per_second"].as_uint64() / 1000000ULL);
                const JVal &mx = spd["max"];
                if (!mx.is_null())
                    info.if_speed_max_mbps = static_cast<uint32_t>(
                        mx["bits_per_unit"].as_uint64() * mx["units_per_second"].as_uint64() / 1000000ULL);
            }
        }
        info.read_lookahead_enabled = root["read_lookahead"]["enabled"].as_bool();
        {
            const JVal &sec = root["ata_security"];
            if (!sec.is_null()) {
                info.security_enabled = sec["enabled"].as_bool();
                info.security_frozen  = sec["frozen"].as_bool();
                info.security_state   = static_cast<uint32_t>(sec["state"].as_uint64());
            }
        }
        info.write_cache_enabled = root["write_cache"]["enabled"].as_bool();
        info.attr_revision = static_cast<uint32_t>(
            root["ata_smart_attributes"]["revision"].as_uint64());

        // Static capability and log-structure fields (cols 33–53)
        {
            const JVal &smart = root["ata_smart_data"];
            if (!smart.is_null()) {
                const JVal &odc = smart["offline_data_collection"];
                info.offline_completion_secs = static_cast<uint32_t>(odc["completion_seconds"].as_uint64());
                const JVal &st = smart["self_test"];
                info.polling_short_min = static_cast<uint32_t>(st["polling_minutes"]["short"].as_uint64());
                info.polling_ext_min   = static_cast<uint32_t>(st["polling_minutes"]["extended"].as_uint64());
                info.polling_conv_min  = static_cast<uint32_t>(st["polling_minutes"]["conveyance"].as_uint64());
                const JVal &cap = smart["capabilities"];
                info.cap_selftests              = cap["self_tests_supported"].as_bool();
                info.cap_conveyance             = cap["conveyance_self_test_supported"].as_bool();
                info.cap_selective              = cap["selective_self_test_supported"].as_bool();
                info.cap_error_logging          = cap["error_logging_supported"].as_bool();
                info.cap_gp_logging             = cap["gp_logging_supported"].as_bool();
                info.cap_exec_offline_immediate = cap["exec_offline_immediate_supported"].as_bool();
                info.cap_offline_aborted_on_cmd = cap["offline_is_aborted_upon_new_cmd"].as_bool();
                info.cap_offline_surface_scan   = cap["offline_surface_scan_supported"].as_bool();
                info.cap_attr_autosave          = cap["attribute_autosave_enabled"].as_bool();
            }
        }
        {
            const JVal &sct = root["ata_sct_capabilities"];
            info.sct_error_recovery  = sct["error_recovery_control_supported"].as_bool();
            info.sct_feature_control = sct["feature_control_supported"].as_bool();
            info.sct_data_table      = sct["data_table_supported"].as_bool();
        }
        info.pending_defects_size = static_cast<uint32_t>(root["ata_pending_defects_log"]["size"].as_uint64());
        {
            const JVal &el = root["ata_smart_error_log"]["extended"];
            info.error_log_revision = static_cast<uint32_t>(el["revision"].as_uint64());
            info.error_log_sectors  = static_cast<uint32_t>(el["sectors"].as_uint64());
        }
        {
            const JVal &stl = root["ata_smart_self_test_log"]["extended"];
            info.selftest_log_revision = static_cast<uint32_t>(stl["revision"].as_uint64());
            info.selftest_log_sectors  = static_cast<uint32_t>(stl["sectors"].as_uint64());
        }
        {
            const JVal &temp = root["ata_sct_temperature_history"]["temperature"];
            info.sct_hist_op_limit_min = static_cast<int32_t>(temp["op_limit_min"].as_int64());
            info.sct_hist_op_limit_max = static_cast<int32_t>(temp["op_limit_max"].as_int64());
            info.sct_hist_limit_min    = static_cast<int32_t>(temp["limit_min"].as_int64());
            info.sct_hist_limit_max    = static_cast<int32_t>(temp["limit_max"].as_int64());
        }

        if (info.logical_block_size > 0 || info.ata_version > 0)
            g_cache.sata_info.push_back(info);
    }

    // SATA health
    {
        const JVal &smart = root["ata_smart_data"];
        if (!smart.is_null()) {
            CacheSataHealthRow h;
            h.device_index         = dev_idx;
            h.overall_status       = health_status_from_passed(root);
            const JVal &odc = smart["offline_data_collection"];
            h.offline_status_value = static_cast<uint32_t>(odc["status"]["value"].as_uint64());
            const JVal &st = smart["self_test"];
            h.selftest_status_value = static_cast<uint32_t>(st["status"]["value"].as_uint64());
            h.power_cycles         = root["power_cycle_count"].as_uint64();
            h.power_on_hours       = root["power_on_time"]["hours"].as_uint64();
            h.error_log_count      = static_cast<uint32_t>(
                root["ata_smart_error_log"]["extended"]["count"].as_uint64());
            h.pending_defects_count = static_cast<uint32_t>(root["ata_pending_defects_log"]["count"].as_uint64());
            h.spare_available_pct        = static_cast<uint32_t>(root["spare_available"]["current_percent"].as_uint64());
            h.spare_available_thresh_pct = static_cast<uint32_t>(root["spare_available"]["threshold_percent"].as_uint64());
            {
                const JVal &stl = root["ata_smart_self_test_log"]["extended"];
                h.selftest_log_count        = static_cast<uint32_t>(stl["count"].as_uint64());
                h.selftest_log_err_total    = static_cast<uint32_t>(stl["error_count_total"].as_uint64());
                h.selftest_log_err_outdated = static_cast<uint32_t>(stl["error_count_outdated"].as_uint64());
            }

            // selective self-test log scalars
            {
                const JVal &ssl = root["ata_smart_selective_self_test_log"];
                h.selective_log_revision       = static_cast<uint32_t>(ssl["revision"].as_uint64());
                h.selective_flags_value        = static_cast<uint32_t>(ssl["flags"]["value"].as_uint64());
                h.selective_remainder_scan     = ssl["flags"]["remainder_scan_enabled"].as_bool();
                h.selective_powerup_resume_min = static_cast<uint32_t>(ssl["power_up_scan_resume_minutes"].as_uint64());
            }

            // log directory scalars
            {
                const JVal &ld = root["ata_log_directory"];
                h.logdir_gp_version        = static_cast<uint32_t>(ld["gp_dir_version"].as_uint64());
                h.logdir_smart_version     = static_cast<uint32_t>(ld["smart_dir_version"].as_uint64());
                h.logdir_smart_multisector = ld["smart_dir_multi_sector"].as_bool();
            }

            h.error_log_revision = static_cast<uint32_t>(
                root["ata_smart_error_log"]["extended"]["revision"].as_uint64());
            {
                const JVal &cap = smart["capabilities"];
                h.cap_exec_offline_immediate = cap["exec_offline_immediate_supported"].as_bool();
                h.cap_offline_aborted_on_cmd = cap["offline_is_aborted_upon_new_cmd"].as_bool();
                h.cap_offline_surface_scan   = cap["offline_surface_scan_supported"].as_bool();
                h.cap_attr_autosave          = cap["attribute_autosave_enabled"].as_bool();
            }
            {
                const JVal &sct = root["ata_sct_status"];
                h.sct_status_format_version = static_cast<uint32_t>(sct["format_version"].as_uint64());
                h.sct_status_sct_version    = static_cast<uint32_t>(sct["sct_version"].as_uint64());
                h.sct_status_device_state   = static_cast<uint32_t>(sct["device_state"]["value"].as_uint64());
                const JVal &temp = sct["temperature"];
                h.sct_temp_power_cycle_min   = static_cast<int32_t>(temp["power_cycle_min"].as_int64());
                h.sct_temp_power_cycle_max   = static_cast<int32_t>(temp["power_cycle_max"].as_int64());
                h.sct_temp_lifetime_min      = static_cast<int32_t>(temp["lifetime_min"].as_int64());
                h.sct_temp_lifetime_max      = static_cast<int32_t>(temp["lifetime_max"].as_int64());
                h.sct_temp_under_limit_count = static_cast<uint32_t>(temp["under_limit_count"].as_uint64());
                h.sct_temp_over_limit_count  = static_cast<uint32_t>(temp["over_limit_count"].as_uint64());
                const JVal &sct_passed = sct["smart_status"]["passed"];
                h.sct_smart_status_passed = sct_passed.is_null()
                    ? root["smart_status"]["passed"].as_bool()
                    : sct_passed.as_bool();
            }

            g_cache.sata_health.push_back(h);
        }
    }

    // SATA SCT ERC table
    {
        struct { const char *key; uint32_t erc_idx; } erc_dirs[] = {{"read", 1u}, {"write", 2u}};
        for (auto &d : erc_dirs) {
            const JVal &e = root["ata_sct_erc"][d.key];
            if (e.is_null()) continue;
            CacheSataErcRow r;
            r.device_index = dev_idx;
            r.erc_index    = d.erc_idx;
            r.enabled      = e["enabled"].as_bool();
            r.deciseconds  = static_cast<uint32_t>(e["deciseconds"].as_uint64());
            g_cache.sata_erc.push_back(r);
        }
    }

    // SATA PHY event counter table
    {
        const JVal &pec = root["sata_phy_event_counters"]["table"];
        if (pec.is_array()) {
            for (std::size_t i = 0; i < pec.size(); ++i) {
                const JVal &entry = pec[i];
                CacheSataPhyEventRow r;
                r.device_index = dev_idx;
                r.id           = static_cast<uint32_t>(entry["id"].as_uint64());
                r.name         = entry["name"].as_string();
                r.size         = static_cast<uint32_t>(entry["size"].as_uint64());
                r.value        = entry["value"].as_uint64();
                r.overflow     = entry["overflow"].as_bool();
                g_cache.sata_phy_events.push_back(r);
            }
        }
    }

    // SATA selective self-test table
    {
        const JVal &ssl = root["ata_smart_selective_self_test_log"]["table"];
        if (ssl.is_array()) {
            for (std::size_t i = 0; i < ssl.size(); ++i) {
                const JVal &entry = ssl[i];
                CacheSataSelectiveTestRow r;
                r.device_index  = dev_idx;
                r.slot          = static_cast<uint32_t>(i + 1);
                r.lba_min       = entry["lba_min"].as_uint64();
                r.lba_max       = entry["lba_max"].as_uint64();
                r.status_value  = static_cast<uint32_t>(entry["status"]["value"].as_uint64());
                r.status_string = entry["status"]["string"].as_string();
                g_cache.sata_selective_tests.push_back(r);
            }
        }
    }

    // Pending defects LBA table
    {
        const JVal &pdl = root["ata_pending_defects_log"]["table"];
        if (pdl.is_array()) {
            for (std::size_t i = 0; i < pdl.size(); ++i) {
                CacheSataPendingDefectRow r;
                r.device_index = dev_idx;
                r.entry_index  = static_cast<uint32_t>(i + 1);
                r.lba          = pdl[i]["lba"].as_uint64();
                g_cache.sata_pending_defects.push_back(r);
            }
        }
    }

    // SATA log directory table
    {
        const JVal &ld = root["ata_log_directory"]["table"];
        if (ld.is_array()) {
            for (std::size_t i = 0; i < ld.size(); ++i) {
                const JVal &entry = ld[i];
                CacheSataLogDirRow r;
                r.device_index  = dev_idx;
                r.address       = static_cast<uint32_t>(entry["address"].as_uint64());
                r.name          = entry["name"].as_string();
                r.readable      = entry["read"].as_bool();
                r.writable      = entry["write"].as_bool();
                r.gp_sectors    = static_cast<uint32_t>(entry["gp_sectors"].as_uint64());
                r.smart_sectors = static_cast<uint32_t>(entry["smart_sectors"].as_uint64());
                g_cache.sata_log_dir.push_back(r);
            }
        }
    }

    // SATA device statistics table
    {
        const JVal &pages = root["ata_device_statistics"]["pages"];
        if (pages.is_array()) {
            for (std::size_t i = 0; i < pages.size(); ++i) {
                const JVal &page = pages[i];
                std::string page_name = page["name"].as_string();
                uint32_t    page_num  = static_cast<uint32_t>(page["number"].as_uint64());
                const JVal &tbl = page["table"];
                if (!tbl.is_array()) continue;
                for (std::size_t j = 0; j < tbl.size(); ++j) {
                    const JVal &entry = tbl[j];
                    CacheSataDevStatRow r;
                    r.device_index = dev_idx;
                    r.page_num     = page_num;
                    r.offset       = static_cast<uint32_t>(entry["offset"].as_uint64());
                    r.page_name    = page_name;
                    r.name         = entry["name"].as_string();
                    r.value        = static_cast<uint64_t>(entry["value"].as_int64());
                    r.flags_value  = static_cast<uint32_t>(entry["flags"]["value"].as_uint64());
                    g_cache.sata_dev_stats.push_back(r);
                }
            }
        }
    }

    // Seagate FARM log (GP Log 0xa6) — supplementary devstat rows and sensors
    if (root["seagate_farm_log"]["supported"].as_bool())
        parse_seagate_farm(dev_idx, root["seagate_farm_log"]);

    // SATA error log (extended) + error cmd table
    {
        const JVal &errs = root["ata_smart_error_log"]["extended"]["table"];
        if (errs.is_array()) {
            for (std::size_t i = 0; i < errs.size(); ++i) {
                const JVal &e = errs[i];
                uint32_t entry_idx = static_cast<uint32_t>(i + 1);

                CacheSataErrorLogRow r;
                r.device_index      = dev_idx;
                r.entry_index       = entry_idx;
                r.error_number      = static_cast<uint32_t>(e["error_number"].as_uint64());
                r.lifetime_hours    = e["lifetime_hours"].as_uint64();
                r.description       = e["error_description"].as_string();
                if (r.description.empty())
                    r.description   = e["description"].as_string();

                const JVal &cr      = e["completion_registers"];
                if (cr.is_object()) {
                    r.comp_reg_error  = static_cast<uint32_t>(cr["error"].as_uint64());
                    r.comp_reg_status = static_cast<uint32_t>(cr["status"].as_uint64());
                    r.lba             = cr["lba"].as_uint64();
                    r.reg_command     = static_cast<uint32_t>(cr["command"].as_uint64());
                    r.reg_count       = static_cast<uint32_t>(cr["count"].as_uint64());
                    r.reg_device      = static_cast<uint32_t>(cr["device"].as_uint64());
                    r.reg_feature     = static_cast<uint32_t>(cr["features"].as_uint64());
                } else {
                    r.comp_reg_error  = static_cast<uint32_t>(e["completion_register_error"].as_uint64());
                    r.comp_reg_status = static_cast<uint32_t>(e["completion_register_status"].as_uint64());
                    r.lba             = e["lba"].as_uint64();
                    r.reg_command     = static_cast<uint32_t>(e["register_command"].as_uint64());
                    r.reg_count       = static_cast<uint32_t>(e["register_count"].as_uint64());
                    r.reg_device      = static_cast<uint32_t>(e["register_device"].as_uint64());
                    r.reg_feature     = static_cast<uint32_t>(e["register_feature"].as_uint64());
                }

                uint64_t state_value = e["device_state"]["value"].as_uint64();
                if (state_value == 0)
                    state_value = e["state"]["value"].as_uint64();
                r.state_value       = static_cast<uint32_t>(state_value) & 0x0fu;
                g_cache.sata_error_log.push_back(r);

                // Error cmd sub-table (previous commands leading to this error)
                const JVal &cmds = e["previous_commands"];
                if (cmds.is_array()) {
                    for (std::size_t j = 0; j < cmds.size(); ++j) {
                        const JVal &c    = cmds[j];
                        const JVal &regs = c["registers"];
                        CacheSataErrorCmdRow cmd;
                        cmd.device_index      = dev_idx;
                        cmd.error_entry_index = entry_idx;
                        cmd.cmd_index         = static_cast<uint32_t>(j + 1);
                        cmd.reg_command       = static_cast<uint32_t>(regs["command"].as_uint64());
                        cmd.reg_count         = static_cast<uint32_t>(regs["count"].as_uint64());
                        cmd.reg_device        = static_cast<uint32_t>(regs["device"].as_uint64());
                        cmd.reg_error         = r.comp_reg_error;
                        cmd.reg_feature       = static_cast<uint32_t>(regs["features"].as_uint64());
                        cmd.reg_lba           = regs["lba"].as_uint64();
                        cmd.reg_status        = r.comp_reg_status;
                        cmd.timestamp_ms      = static_cast<uint32_t>(c["powerup_milliseconds"].as_uint64());
                        cmd.description       = c["command_name"].as_string();
                        g_cache.sata_error_cmds.push_back(cmd);
                    }
                }
            }
        }
    }

    // Sort sata_dev_stats by (device_index, page_num, offset) so the SNMP
    // iterator returns rows in OID-ascending order.  FARM pages (100-105)
    // interleave with ATA device-stats page 255 and must be sorted into place.
    std::sort(g_cache.sata_dev_stats.begin(), g_cache.sata_dev_stats.end(),
              [](const CacheSataDevStatRow &a, const CacheSataDevStatRow &b) {
                  return sort_key(a) < sort_key(b);
              });

    // Update last-change timestamps only when content hash changed
    {
        struct timespec now_ts {}; clock_gettime(CLOCK_REALTIME, &now_ts);
        auto &hv = g_cache.table_hashes;
        update_table_ts(TABLE_DEVICE,        g_cache.ts_device_table,        hv[TABLE_DEVICE],        hash_vector(g_cache.devices),              now_ts);
        update_table_ts(TABLE_SATA_INFO,     g_cache.ts_sata_info,           hv[TABLE_SATA_INFO],     hash_vector(g_cache.sata_info),            now_ts);
        update_table_ts(TABLE_SATA_HEALTH,   g_cache.ts_sata_health,         hv[TABLE_SATA_HEALTH],   hash_vector(g_cache.sata_health),          now_ts);
        update_table_ts(TABLE_SATA_ATTR,     g_cache.ts_sata_attr,           hv[TABLE_SATA_ATTR],     hash_vector(g_cache.sata_attrs),           now_ts);
        update_table_ts(TABLE_SATA_ERRLOG,   g_cache.ts_sata_error_log,      hv[TABLE_SATA_ERRLOG],   hash_vector(g_cache.sata_error_log),       now_ts);
        update_table_ts(TABLE_SATA_ERRCMD,   g_cache.ts_sata_error_cmd,      hv[TABLE_SATA_ERRCMD],   hash_vector(g_cache.sata_error_cmds),      now_ts);
        update_table_ts(TABLE_SATA_SELFTEST, g_cache.ts_sata_selftest,       hv[TABLE_SATA_SELFTEST], hash_vector(g_cache.sata_selftests),       now_ts);
        update_table_ts(TABLE_SATA_ERC,      g_cache.ts_sata_erc,            hv[TABLE_SATA_ERC],      hash_vector(g_cache.sata_erc),             now_ts);
        update_table_ts(TABLE_SATA_PHY,      g_cache.ts_sata_phy_event,      hv[TABLE_SATA_PHY],      hash_vector(g_cache.sata_phy_events),      now_ts);
        update_table_ts(TABLE_SATA_SELTEST,  g_cache.ts_sata_selective_test, hv[TABLE_SATA_SELTEST],  hash_vector(g_cache.sata_selective_tests), now_ts);
        update_table_ts(TABLE_SATA_PENDING,  g_cache.ts_sata_pending_defects,hv[TABLE_SATA_PENDING],  hash_vector(g_cache.sata_pending_defects), now_ts);
        update_table_ts(TABLE_SATA_LOGDIR,   g_cache.ts_sata_log_dir,        hv[TABLE_SATA_LOGDIR],   hash_vector(g_cache.sata_log_dir),         now_ts);
        update_table_ts(TABLE_SATA_DEVSTAT,  g_cache.ts_sata_dev_stat,       hv[TABLE_SATA_DEVSTAT],  hash_vector(g_cache.sata_dev_stats),       now_ts);
        update_table_ts(TABLE_SENSOR,        g_cache.ts_sensor,              hv[TABLE_SENSOR],        hash_vector(g_cache.sensors),              now_ts);

        // Per-(device, tableId) ByDevice timestamps for all 12 SATA tables.
        {
            auto upd_by_dev = [&](uint32_t tid, uint64_t new_h) {
                uint64_t key = ((uint64_t)dev_idx << 32) | tid;
                auto &prev = g_cache.hash_sata_by_dev[key];
                if (new_h != prev) {
                    prev = new_h;
                    g_cache.ts_sata_by_dev[key] = now_ts;
                    state_db_update_by_dev(dev_idx, tid, new_h, now_ts.tv_sec);
                }
            };
            upd_by_dev( 1, hash_vector_for_device(g_cache.sata_info,             dev_idx));
            upd_by_dev( 2, hash_vector_for_device(g_cache.sata_health,           dev_idx));
            upd_by_dev( 3, hash_vector_for_device(g_cache.sata_attrs,            dev_idx));
            upd_by_dev( 4, hash_vector_for_device(g_cache.sata_error_log,        dev_idx));
            upd_by_dev( 5, hash_vector_for_device(g_cache.sata_error_cmds,       dev_idx));
            upd_by_dev( 6, hash_vector_for_device(g_cache.sata_selftests,        dev_idx));
            upd_by_dev( 7, hash_vector_for_device(g_cache.sata_erc,              dev_idx));
            upd_by_dev( 8, hash_vector_for_device(g_cache.sata_phy_events,       dev_idx));
            upd_by_dev( 9, hash_vector_for_device(g_cache.sata_selective_tests,  dev_idx));
            upd_by_dev(10, hash_vector_for_device(g_cache.sata_log_dir,          dev_idx));
            upd_by_dev(11, hash_vector_for_device(g_cache.sata_dev_stats,        dev_idx));
            upd_by_dev(12, hash_vector_for_device(g_cache.sata_pending_defects,  dev_idx));
        }
        // Per-page BySubindex timestamps for devstat — each page advances when any of its rows change.
        // errcmd BySubindex reuses ts_sata_by_dev[key|5] set above.
        {
            std::unordered_map<uint32_t, TableHasher> page_hashers;
            for (const auto &r : g_cache.sata_dev_stats) {
                if (r.device_index != dev_idx) continue;
                hash_row(page_hashers[r.page_num], r);
            }
            for (auto &[page_num, hasher] : page_hashers) {
                uint64_t key = ((uint64_t)dev_idx << 32) | page_num;
                uint64_t new_h = hasher.value();
                auto &prev = g_cache.hash_sata_devstat_by_page[key];
                if (new_h != prev) {
                    prev = new_h;
                    g_cache.ts_sata_devstat_by_page[key] = now_ts;
                    state_db_update_devstat_page(dev_idx, page_num, new_h, now_ts.tv_sec);
                }
            }
        }
        g_cache.rebuild_sata_subidx_unique(dev_idx);
    }
}

static void parse_scsi(uint32_t dev_idx, const JVal &root) {
    g_cache.clear_device_data(dev_idx);

    if (g_verbosity >= 2)
        syslog(LOG_DEBUG, "datasrc: SCSI/SAS dev_idx=%u: no sensor rows emitted (protocol has no temp attr mapping)", dev_idx);

    CacheSasHealthRow h;
    h.device_index      = dev_idx;
    h.overall_status    = health_status_from_passed(root);
    h.grown_defect_count= static_cast<uint32_t>(root["scsi_grown_defect_list"].as_uint64());
    g_cache.sas_health.push_back(h);

    // Error counter log: read and write directions
    const JVal &ecl = root["scsi_error_counter_log"];
    if (!ecl.is_null()) {
        struct { const char *key; int dir; } dirs[] = {
            { "read",  1 },
            { "write", 2 },
        };
        for (auto &d : dirs) {
            const JVal &dir_obj = ecl[d.key];
            if (dir_obj.is_null()) continue;
            CacheSasErrorCounterRow r;
            r.device_index   = dev_idx;
            r.direction      = d.dir;
            r.ecc_fast       = dir_obj["errors_corrected_by_eccfast"].as_uint64();
            r.ecc_delayed    = dir_obj["errors_corrected_by_eccdelayed"].as_uint64();
            r.rereads_rewrites = dir_obj["errors_corrected_by_rereads_rewrites"].as_uint64();
            r.total_corrected= dir_obj["total_errors_corrected"].as_uint64();
            r.algorithm_invoked = dir_obj["correction_algorithm_invocations"].as_uint64();
            r.uncorrected    = dir_obj["total_uncorrected_errors"].as_uint64();
            // gigabytes_processed may be a string ("47221.194"), float, int, or null
            const JVal &gbp  = dir_obj["gigabytes_processed"];
            double gb;
            if (gbp.is_string())
                gb = strtod(gbp.as_string().c_str(), nullptr);
            else if (gbp.is_int())
                gb = static_cast<double>(gbp.ival);
            else if (gbp.is_uint())
                gb = static_cast<double>(gbp.uval);
            else if (gbp.type == JVal::J_FLOAT)
                gb = gbp.fval;
            else
                gb = 0.0;
            r.bytes_processed= static_cast<uint64_t>(gb * 1e9);
            g_cache.sas_error_counters.push_back(r);
        }
    }

    // Self-test log
    const JVal &stlog = root["scsi_self_test_log"]["extended"]["table"];
    if (stlog.is_array()) {
        for (std::size_t i = 0; i < stlog.size(); ++i) {
            const JVal &e = stlog[i];
            CacheSasSelfTestRow r;
            r.device_index  = dev_idx;
            r.entry_index   = static_cast<uint32_t>(i + 1);
            r.type          = static_cast<int>(e["type"]["value"].as_int64());
            r.result        = static_cast<int>(e["status"]["value"].as_int64());
            r.result_str    = e["status"]["string"].as_string();
            r.passed        = e["status"]["passed"].as_bool();
            r.power_on_hours= e["lifetime_hours"].as_uint64();
            const JVal &lba = e["lba_of_first_error"];
            r.lba_first_error = lba.is_null() ? 0 : lba.as_uint64();
            g_cache.sas_selftests.push_back(r);
        }
    }

    // SAS info
    {
        CacheSasInfoRow info;
        info.device_index        = dev_idx;
        info.vendor              = root["scsi_vendor"].as_string();
        info.product             = root["scsi_product"].as_string();
        info.revision            = root["scsi_revision"].as_string();
        info.compliance          = root["scsi_version"].as_string();
        info.rotation_rate       = static_cast<uint32_t>(root["rotation_rate"].as_uint64());
        info.form_factor         = root["form_factor"]["name"].as_string();
        info.logical_block_size  = static_cast<uint32_t>(root["logical_block_size"].as_uint64());
        info.physical_block_size = static_cast<uint32_t>(root["physical_block_size"].as_uint64());
        info.user_capacity_bytes = root["user_capacity"]["bytes"].as_uint64();
        info.power_cycles        = root["power_cycle_count"].as_uint64();
        info.power_on_hours      = root["power_on_time"]["hours"].as_uint64();
        if (!info.vendor.empty() || !info.product.empty() || info.user_capacity_bytes > 0)
            g_cache.sas_info.push_back(info);
    }

    // Background scan
    {
        const JVal &bgs = root["scsi_background_scan"];
        if (!bgs.is_null()) {
            CacheSasBgScanRow r;
            r.device_index      = dev_idx;
            const JVal &st2 = bgs["status"];
            r.status_value      = static_cast<int>(st2["value"].as_int64());
            r.status_string     = st2["string"].as_string();
            r.progress_percent  = static_cast<uint32_t>(bgs["scan_progress"].as_uint64());
            r.medium_scans      = bgs["number_of_background_medium_scans_performed"].as_uint64();
            r.scans_performed   = bgs["number_of_background_pre_scan_scans_performed"].as_uint64();
            g_cache.sas_bgscan.push_back(r);
        }
    }

    // Update last-change timestamps only when content hash changed
    {
        struct timespec now_ts {}; clock_gettime(CLOCK_REALTIME, &now_ts);
        auto &hv = g_cache.table_hashes;
        update_table_ts(TABLE_DEVICE,      g_cache.ts_device_table,    hv[TABLE_DEVICE],      hash_vector(g_cache.devices),           now_ts);
        update_table_ts(TABLE_SAS_INFO,    g_cache.ts_sas_info,        hv[TABLE_SAS_INFO],    hash_vector(g_cache.sas_info),          now_ts);
        update_table_ts(TABLE_SAS_HEALTH,  g_cache.ts_sas_health,      hv[TABLE_SAS_HEALTH],  hash_vector(g_cache.sas_health),        now_ts);
        update_table_ts(TABLE_SAS_ERRCNT,  g_cache.ts_sas_error_counter,hv[TABLE_SAS_ERRCNT], hash_vector(g_cache.sas_error_counters),now_ts);
        update_table_ts(TABLE_SAS_SELFTEST,g_cache.ts_sas_selftest,    hv[TABLE_SAS_SELFTEST],hash_vector(g_cache.sas_selftests),     now_ts);
        update_table_ts(TABLE_SAS_BGSCAN,  g_cache.ts_sas_bgscan,      hv[TABLE_SAS_BGSCAN],  hash_vector(g_cache.sas_bgscan),        now_ts);
    }
}

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

static void log_device_loaded(uint32_t dev_idx, DeviceProto proto,
                               const std::string &dev_path) {
    char buf[320];

    if (proto == PROTO_NVME) {
        for (const auto &h : g_cache.nvme_health) {
            if (h.device_index != dev_idx) continue;
            const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
            const std::string &model = dev ? dev->model_name : std::string{};
            snprintf(buf, sizeof(buf),
                "loaded %s [NVMe] model=\"%s\" spare=%u%% used=%u%% "
                "poh=%lluh media_err=%llu",
                dev_path.c_str(), model.c_str(),
                h.available_spare_pct, h.percentage_used,
                (unsigned long long)h.power_on_hours,
                (unsigned long long)h.media_errors);
            syslog(LOG_INFO, "%s", buf);
            return;
        }
    } else if (proto == PROTO_ATA || proto == PROTO_SAT) {
        for (const auto &h : g_cache.sata_health) {
            if (h.device_index != dev_idx) continue;
            const CacheDeviceRow *dv = g_cache.find_device(dev_idx);
            const std::string &model = dv ? dv->model_name : std::string{};
            size_t n_attrs = 0;
            for (const auto &a : g_cache.sata_attrs)
                if (a.device_index == dev_idx) ++n_attrs;
            const char *health_str = (h.overall_status == 1) ? "passed"
                                   : (h.overall_status == 2) ? "FAILED" : "unknown";
            snprintf(buf, sizeof(buf),
                "loaded %s [%s] model=\"%s\" health=%s poh=%lluh attrs=%zu",
                dev_path.c_str(), (proto == PROTO_SAT) ? "SAT" : "ATA",
                model.c_str(), health_str,
                (unsigned long long)h.power_on_hours, n_attrs);
            syslog(LOG_INFO, "%s", buf);
            return;
        }
    } else if (proto == PROTO_SCSI || proto == PROTO_SAS) {
        for (const auto &h : g_cache.sas_health) {
            if (h.device_index != dev_idx) continue;
            const char *health_str = (h.overall_status == 1) ? "passed"
                                   : (h.overall_status == 2) ? "FAILED" : "unknown";
            snprintf(buf, sizeof(buf),
                "loaded %s [%s] health=%s grown_defects=%u",
                dev_path.c_str(), (proto == PROTO_SAS) ? "SAS" : "SCSI",
                health_str, h.grown_defect_count);
            syslog(LOG_INFO, "%s", buf);
            return;
        }
    }
    syslog(LOG_INFO, "loaded %s [proto=%d] (no health data)", dev_path.c_str(), (int)proto);
}

static void log_cache_summary() {
    size_t n_total = g_cache.devices.size();
    size_t n_nvme = 0, n_ata = 0, n_sas = 0;
    for (const auto &d : g_cache.devices) {
        switch (d.proto) {
        case PROTO_NVME:                  ++n_nvme; break;
        case PROTO_ATA: case PROTO_SAT:   ++n_ata;  break;
        case PROTO_SCSI: case PROTO_SAS:  ++n_sas;  break;
        default: break;
        }
    }
    syslog(LOG_NOTICE,
        "cache: %zu device(s) — %zu NVMe, %zu ATA/SAT, %zu SAS/SCSI",
        n_total, n_nvme, n_ata, n_sas);
}

// ---------------------------------------------------------------------------
// State snapshot for change detection and trap dispatch
// ---------------------------------------------------------------------------

struct DeviceSnapshot {
    int      health_status              { -1 };
    uint32_t last_failed_selftest_entry { 0 };
    uint32_t last_failed_nvme_number    { 0 };
    std::vector<uint32_t>             failing_attr_ids;
    std::unordered_map<int, uint64_t> uncorrected_before;
};

static DeviceSnapshot capture_snapshot(uint32_t dev_idx, DeviceProto proto) {
    DeviceSnapshot snap;

    if (proto == PROTO_NVME) {
        for (const auto &h : g_cache.nvme_health)
            if (h.device_index == dev_idx) { snap.health_status = h.overall_status; break; }
        for (const auto &st : g_cache.nvme_selftests)
            if (st.device_index == dev_idx && st.result != 0)
                snap.last_failed_nvme_number =
                    std::max(snap.last_failed_nvme_number, st.number);
    } else if (proto == PROTO_ATA || proto == PROTO_SAT) {
        for (const auto &h : g_cache.sata_health)
            if (h.device_index == dev_idx) { snap.health_status = h.overall_status; break; }
        for (const auto &st : g_cache.sata_selftests)
            if (st.device_index == dev_idx && !st.passed)
                snap.last_failed_selftest_entry =
                    std::max(snap.last_failed_selftest_entry, st.entry_index);
        for (const auto &a : g_cache.sata_attrs)
            if (a.device_index == dev_idx && a.threshold > 0 && a.value <= a.threshold)
                snap.failing_attr_ids.push_back(a.attr_id);
    } else if (proto == PROTO_SCSI || proto == PROTO_SAS) {
        for (const auto &h : g_cache.sas_health)
            if (h.device_index == dev_idx) { snap.health_status = h.overall_status; break; }
        for (const auto &st : g_cache.sas_selftests)
            if (st.device_index == dev_idx && !st.passed)
                snap.last_failed_selftest_entry =
                    std::max(snap.last_failed_selftest_entry, st.entry_index);
        for (const auto &ec : g_cache.sas_error_counters)
            if (ec.device_index == dev_idx)
                snap.uncorrected_before[ec.direction] = ec.uncorrected;
    }

    return snap;
}

void agentxd_datasrc_remove_device(uint32_t dev_idx) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    if (dev)
        notify_device_removed(dev_idx, dev->name, dev->path, (int)dev->proto);
    g_cache.remove_device(dev_idx);
    state_db_remove_device(dev_idx);
}

static void dispatch_notifications(uint32_t dev_idx, DeviceProto proto,
                                   const DeviceSnapshot &snap, bool is_new) {
    if (is_new) {
        if (s_initial_scan_done)
            notify_device_discovered(dev_idx);
        return;
    }

    int new_health = -1;
    if (proto == PROTO_NVME) {
        for (const auto &h : g_cache.nvme_health)
            if (h.device_index == dev_idx) { new_health = h.overall_status; break; }
    } else if (proto == PROTO_ATA || proto == PROTO_SAT) {
        for (const auto &h : g_cache.sata_health)
            if (h.device_index == dev_idx) { new_health = h.overall_status; break; }
    } else if (proto == PROTO_SCSI || proto == PROTO_SAS) {
        for (const auto &h : g_cache.sas_health)
            if (h.device_index == dev_idx) { new_health = h.overall_status; break; }
    }
    if (snap.health_status != -1 && new_health != -1 && snap.health_status != new_health)
        notify_device_health_changed(dev_idx, new_health);

    if (proto == PROTO_NVME) {
        uint32_t new_failed = 0;
        const CacheNvmeSelfTestRow *worst = nullptr;
        for (const auto &st : g_cache.nvme_selftests) {
            if (st.device_index != dev_idx || st.result == 0)
                continue;
            if (st.number > new_failed) { new_failed = st.number; worst = &st; }
        }
        if (worst && new_failed > snap.last_failed_nvme_number)
            notify_nvme_selftest_failed(dev_idx, *worst);
    } else if (proto == PROTO_ATA || proto == PROTO_SAT) {
        uint32_t new_failed = 0;
        const CacheSataSelfTestRow *worst = nullptr;
        for (const auto &st : g_cache.sata_selftests) {
            if (st.device_index != dev_idx || st.passed)
                continue;
            if (st.entry_index > new_failed) { new_failed = st.entry_index; worst = &st; }
        }
        if (worst && new_failed > snap.last_failed_selftest_entry)
            notify_sata_selftest_failed(dev_idx, *worst);
    } else if (proto == PROTO_SCSI || proto == PROTO_SAS) {
        uint32_t new_failed = 0;
        const CacheSasSelfTestRow *worst = nullptr;
        for (const auto &st : g_cache.sas_selftests) {
            if (st.device_index != dev_idx || st.passed)
                continue;
            if (st.entry_index > new_failed) { new_failed = st.entry_index; worst = &st; }
        }
        if (worst && new_failed > snap.last_failed_selftest_entry)
            notify_sas_selftest_failed(dev_idx, *worst);
    }

    if (proto == PROTO_ATA || proto == PROTO_SAT) {
        for (const auto &a : g_cache.sata_attrs) {
            if (a.device_index != dev_idx)
                continue;
            if (a.threshold == 0 || a.value > a.threshold)
                continue;
            bool was_failing = std::find(snap.failing_attr_ids.begin(),
                                         snap.failing_attr_ids.end(),
                                         a.attr_id) != snap.failing_attr_ids.end();
            if (!was_failing)
                notify_sata_attr_failing(dev_idx, a);
        }
    }

    if (proto == PROTO_SCSI || proto == PROTO_SAS) {
        for (const auto &ec : g_cache.sas_error_counters) {
            if (ec.device_index != dev_idx)
                continue;
            auto it = snap.uncorrected_before.find(ec.direction);
            if (it != snap.uncorrected_before.end() && ec.uncorrected > it->second)
                notify_sas_uncorrected_errors_increased(dev_idx, ec);
        }
    }

    for (const auto &sensor : g_cache.sensors) {
        if (sensor.device_index != dev_idx)
            continue;
        if (sensor.has_high_critical && sensor.value >= sensor.high_critical)
            notify_sensor_high_critical(dev_idx, sensor);
        else if (sensor.has_high_warning && sensor.value >= sensor.high_warning)
            notify_sensor_high_warning(dev_idx, sensor);

        if (sensor.has_low_critical && sensor.value <= sensor.low_critical)
            notify_sensor_low_critical(dev_idx, sensor);
        else if (sensor.has_low_warning && sensor.value <= sensor.low_warning)
            notify_sensor_low_warning(dev_idx, sensor);
    }
}

// ---------------------------------------------------------------------------
// Parse one JSON state file into the cache
// ---------------------------------------------------------------------------

static void process_json_file(const std::string &filepath) {
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: process_json_file '%s'", filepath.c_str());
    struct stat st;
    if (stat(filepath.c_str(), &st) != 0) {
        syslog(LOG_WARNING, "stat(%s): %s", filepath.c_str(), strerror(errno));
        return;
    }
    time_t mtime = st.st_mtime;

    std::string err;
    JVal root = json_load_file(filepath, err);
    if (!err.empty()) {
        syslog(LOG_WARNING, "%s: JSON parse error: %s", filepath.c_str(), err.c_str());
        auto it = s_file_device_index.find(filepath);
        if (it != s_file_device_index.end()) {
            for (auto &row : g_cache.devices) {
                if (row.index != it->second)
                    continue;
                row.poll_result = POLL_FAILED;
                row.poll_exit_status = 1;
                ++row.consec_fail_count;
                if (row.consec_fail_count >= g_poll_failure_threshold)
                    notify_device_polling_failed(row.index, (int)row.poll_result);
                break;
            }
        }
        return;
    }

    // Device path and protocol come from the JSON itself
    std::string dev_path = root["device"]["name"].as_string();
    std::string protocol = root["device"]["protocol"].as_string();

    if (g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: %s → device.name='%s' device.protocol='%s'",
               filepath.c_str(), dev_path.c_str(), protocol.c_str());

    if (dev_path.empty()) {
        syslog(LOG_WARNING, "%s: missing device.name", filepath.c_str());
        return;
    }

    // Map protocol string to enum
    DeviceProto proto = PROTO_UNKNOWN;
    if (protocol == "ATA")  proto = PROTO_ATA;
    else if (protocol == "NVMe") proto = PROTO_NVME;
    else if (protocol == "SCSI") proto = PROTO_SCSI;
    else if (protocol == "SAT")  proto = PROTO_SAT;
    else if (protocol == "SAS")  proto = PROTO_SAS;

    if (proto == PROTO_UNKNOWN) {
        syslog(LOG_WARNING, "datasrc: %s: unrecognized protocol '%s' — skipping",
               filepath.c_str(), protocol.c_str());
        return;
    }

    std::string dev_serial = root["serial_number"].as_string();
    std::string dev_model  = root["model_name"].as_string();
    if (dev_model.empty())
        dev_model = root["scsi_model_name"].as_string();
    uint32_t hint_idx = fnv1a32(dev_serial + '|' + dev_model);
    uint32_t dev_idx = g_cache.upsert_device(dev_path, proto, hint_idx);
    s_file_device_index[filepath] = dev_idx;
    if (g_verbosity >= 2)
        syslog(LOG_DEBUG, "datasrc: dev_idx=%u for '%s'", dev_idx, dev_path.c_str());

    bool is_new_device = false;
    for (const auto &row : g_cache.devices) {
        if (row.index == dev_idx) {
            is_new_device = (row.last_json_mtime == 0);
            break;
        }
    }
    DeviceSnapshot snap = capture_snapshot(dev_idx, proto);

    // Update device row metadata
    {
        struct timespec t_uris;
        clock_gettime(CLOCK_MONOTONIC, &t_uris);
        for (auto &row : g_cache.devices) {
            if (row.index != dev_idx) continue;
            {
                const std::string &p = dev_path;
                size_t slash = p.rfind('/');
                row.name = (slash != std::string::npos) ? p.substr(slash + 1) : p;
            }
            populate_device_uris(row, proto);
            row.last_poll_time    = root["local_time"]["time_t"].as_int64();
            row.last_json_mtime   = mtime;
            row.poll_result       = POLL_OK;
            row.consec_fail_count = 0;
            row.serial_number     = dev_serial;
            row.model_name        = dev_model;
            row.model_family      = root["model_family"].as_string();
            row.firmware_version  = root["firmware_version"].as_string();
            { const JVal &ww = root["wwn"];
              row.wwn = ww.is_null() ? std::string{} : format_wwn(ww); }
            break;
        }
        long uris_ms = elapsed_ms(t_uris);
        if (uris_ms >= 10)
            syslog(LOG_WARNING, "datasrc: populate_device_uris '%s' took %ldms",
                   dev_path.c_str(), uris_ms);
        else if (g_verbosity >= 1)
            syslog(LOG_DEBUG, "datasrc: populate_device_uris '%s' took %ldms",
                   dev_path.c_str(), uris_ms);
    }

    size_t sensors_before = g_cache.sensors.size();

    // Parse protocol-specific data
    {
        struct timespec t_parse;
        clock_gettime(CLOCK_MONOTONIC, &t_parse);
        if (proto == PROTO_NVME)
            parse_nvme(dev_idx, root);
        else if (proto == PROTO_ATA || proto == PROTO_SAT)
            parse_ata(dev_idx, root);
        else if (proto == PROTO_SCSI || proto == PROTO_SAS)
            parse_scsi(dev_idx, root);
        long parse_ms = elapsed_ms(t_parse);
        if (parse_ms >= 10)
            syslog(LOG_WARNING, "datasrc: parse '%s' took %ldms",
                   dev_path.c_str(), parse_ms);
        else if (g_verbosity >= 1)
            syslog(LOG_DEBUG, "datasrc: parse '%s' took %ldms",
                   dev_path.c_str(), parse_ms);
    }

    size_t sensors_added = g_cache.sensors.size() - sensors_before;
    if (g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: '%s' added %zu sensor row(s) (total=%zu)",
               dev_path.c_str(), sensors_added, g_cache.sensors.size());

    log_device_loaded(dev_idx, proto, dev_path);
    {
        struct timespec t_notif;
        clock_gettime(CLOCK_MONOTONIC, &t_notif);
        dispatch_notifications(dev_idx, proto, snap, is_new_device);
        long notif_ms = elapsed_ms(t_notif);
        if (notif_ms >= 10)
            syslog(LOG_WARNING, "datasrc: dispatch_notifications '%s' took %ldms",
                   dev_path.c_str(), notif_ms);
        else if (g_verbosity >= 1)
            syslog(LOG_DEBUG, "datasrc: dispatch_notifications '%s' took %ldms",
                   dev_path.c_str(), notif_ms);
    }

    syslog(LOG_DEBUG, "datasrc: process_json_file '%s' done in %ldms",
           filepath.c_str(), elapsed_ms(t0));
}

// ---------------------------------------------------------------------------
// Initial directory scan
// ---------------------------------------------------------------------------

static void scan_state_dir() {
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: scanning state_dir '%s'", s_state_dir.c_str());
    DIR *d = opendir(s_state_dir.c_str());
    if (!d) {
        syslog(LOG_ERR, "opendir(%s): %s", s_state_dir.c_str(), strerror(errno));
        return;
    }
    int n_total = 0, n_accepted = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        ++n_total;
        DeviceProto proto;
        if (!identify_state_file_proto(name, proto)) continue;
        ++n_accepted;
        process_json_file(s_state_dir + "/" + name);
    }
    closedir(d);
    s_initial_scan_done = true;
    long scan_ms = elapsed_ms(t0);
    g_cache.last_scan_time = time(nullptr);
    g_cache.last_scan_ms   = static_cast<uint32_t>(scan_ms < 0 ? 0 : scan_ms);
    if (g_verbosity >= 1)
        syslog(LOG_DEBUG, "datasrc: scan done: %d file(s) found, %d accepted — sensors=%zu ts_sensor=%ld elapsed=%ldms",
               n_total, n_accepted,
               g_cache.sensors.size(), (long)g_cache.ts_sensor.tv_sec, scan_ms);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool agentxd_datasrc_init(const std::string &state_dir) {
    s_state_dir = state_dir;
    s_initial_scan_done = false;
    s_file_device_index.clear();

    // Ensure trailing slash is absent for consistent path concatenation
    while (!s_state_dir.empty() && s_state_dir.back() == '/')
        s_state_dir.pop_back();

    // Validate that the directory exists
    struct stat st;
    if (stat(s_state_dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        syslog(LOG_ERR, "state_dir '%s' does not exist or is not a directory",
               s_state_dir.c_str());
        return false;
    }

    // Detect smartd running without --jsonstate
    if (smartd_pid_file_exists() && !state_dir_has_json(s_state_dir)) {
        syslog(LOG_ERR,
               "smartd appears to be running but '%s' contains no JSON state files. "
               "Configure smartd with '--jsonstate %s/' in smartd.conf and restart smartd.",
               s_state_dir.c_str(), s_state_dir.c_str());
        return false;
    }

    // Set up inotify
    s_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (s_inotify_fd < 0) {
        syslog(LOG_ERR, "inotify_init1: %s", strerror(errno));
        return false;
    }

    s_watch_wd = inotify_add_watch(s_inotify_fd, s_state_dir.c_str(),
                                   IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM);
    if (s_watch_wd < 0) {
        syslog(LOG_ERR, "inotify_add_watch(%s): %s",
               s_state_dir.c_str(), strerror(errno));
        close(s_inotify_fd);
        s_inotify_fd = -1;
        return false;
    }

    // Load current state from all existing JSON files
    scan_state_dir();
    log_cache_summary();
    return true;
}

void agentxd_datasrc_handle_events() {
    if (s_inotify_fd < 0) return;

    // inotify events can be batched; read all available
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;) {
        ssize_t n = read(s_inotify_fd, buf, sizeof(buf));
        if (n <= 0) break; // EAGAIN when no more events

        const char *p = buf;
        while (p < buf + n) {
            const struct inotify_event *ev =
                reinterpret_cast<const struct inotify_event *>(p);
            p += sizeof(struct inotify_event) + ev->len;

            if (ev->len == 0) continue;
            std::string name = ev->name;

            DeviceProto proto;
            if (!identify_state_file_proto(name, proto)) continue;

            std::string filepath = s_state_dir + "/" + name;
            if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                auto it = s_file_device_index.find(filepath);
                if (it != s_file_device_index.end()) {
                    agentxd_datasrc_remove_device(it->second);
                    s_file_device_index.erase(it);
                }
                continue;
            }

            process_json_file(filepath);
        }
    }
}

int agentxd_datasrc_fd() {
    return s_inotify_fd;
}

void agentxd_datasrc_check_staleness(unsigned cache_timeout) {
    time_t now = time(nullptr);
    time_t stale_threshold = static_cast<time_t>(cache_timeout) * 2;

    for (const auto &dev : g_cache.devices) {
        if (dev.last_json_mtime == 0) continue;
        time_t age = now - dev.last_json_mtime;
        if (age > stale_threshold) {
            syslog(LOG_WARNING,
                   "device %s: JSON state file not updated for %ld seconds "
                   "(threshold %u s). Is smartd still running with --jsonstate?",
                   dev.path.c_str(), (long)age, cache_timeout * 2);
        }
    }
}

void agentxd_datasrc_load_file(const std::string &filepath) {
    process_json_file(filepath);
}

void agentxd_datasrc_shutdown() {
    if (s_watch_wd >= 0 && s_inotify_fd >= 0)
        inotify_rm_watch(s_inotify_fd, s_watch_wd);
    if (s_inotify_fd >= 0) {
        close(s_inotify_fd);
        s_inotify_fd = -1;
    }
    s_watch_wd = -1;
}
