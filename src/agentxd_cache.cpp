// agentxd_cache.cpp — AgentxCache implementation

#include "agentxd_cache.h"

#include <algorithm>
#include <unordered_set>

AgentxCache g_cache;

template<typename Vec>
static void erase_by_device(Vec &vec, uint32_t idx) {
    vec.erase(
        std::remove_if(vec.begin(), vec.end(),
                       [idx](const typename Vec::value_type &row) {
                           return row.device_index == idx;
                       }),
        vec.end());
}

void AgentxCache::clear_device_data(uint32_t idx) {
    erase_by_device(nvme_health,        idx);
    erase_by_device(nvme_selftests,     idx);
    erase_by_device(nvme_controllers,   idx);
    erase_by_device(nvme_namespaces,    idx);
    erase_by_device(nvme_error_log,     idx);
    erase_by_device(nvme_capabilities,  idx);
    erase_by_device(nvme_power_states,  idx);
    erase_by_device(nvme_lba_formats,   idx);
    erase_by_device(sata_attrs,         idx);
    erase_by_device(sata_selftests,     idx);
    erase_by_device(sata_info,          idx);
    erase_by_device(sata_health,        idx);
    erase_by_device(sata_error_log,     idx);
    erase_by_device(sata_error_cmds,    idx);
    erase_by_device(sata_erc,           idx);
    erase_by_device(sata_phy_events,    idx);
    erase_by_device(sata_selective_tests,  idx);
    erase_by_device(sata_pending_defects,  idx);
    erase_by_device(sata_log_dir,          idx);
    erase_by_device(sata_dev_stats,     idx);
    erase_by_device(sas_health,         idx);
    erase_by_device(sas_error_counters, idx);
    erase_by_device(sas_selftests,      idx);
    erase_by_device(sas_info,           idx);
    erase_by_device(sas_bgscan,         idx);
    erase_by_device(sensors,            idx);
}

void AgentxCache::remove_device(uint32_t idx) {
    devices.erase(
        std::remove_if(devices.begin(), devices.end(),
                       [idx](const CacheDeviceRow &r) { return r.index == idx; }),
        devices.end());
    clear_device_data(idx);

    // Purge per-(device, tableId) ByDevice entries.
    for (uint32_t tid = 1; tid <= 12; ++tid) {
        uint64_t key = ((uint64_t)idx << 32) | tid;
        hash_sata_by_dev.erase(key);
        ts_sata_by_dev.erase(key);
    }
    // Purge per-page devstat entries for this device (high 32 bits of key == idx).
    for (auto it = hash_sata_devstat_by_page.begin(); it != hash_sata_devstat_by_page.end(); ) {
        if ((uint32_t)(it->first >> 32) == idx) it = hash_sata_devstat_by_page.erase(it);
        else ++it;
    }
    for (auto it = ts_sata_devstat_by_page.begin(); it != ts_sata_devstat_by_page.end(); ) {
        if ((uint32_t)(it->first >> 32) == idx) it = ts_sata_devstat_by_page.erase(it);
        else ++it;
    }
    rebuild_sata_subidx_unique(idx);

    // Purge alarm state for this device.
    for (auto it = sensor_alarm_state.begin(); it != sensor_alarm_state.end(); ) {
        if ((uint32_t)(it->first >> 32) == idx) it = sensor_alarm_state.erase(it);
        else ++it;
    }
    for (auto it = sensor_alarm_last_sent.begin(); it != sensor_alarm_last_sent.end(); ) {
        if ((uint32_t)(it->first >> 32) == idx) it = sensor_alarm_last_sent.erase(it);
        else ++it;
    }
    sata_attr_alarm.erase(idx);
    for (auto it = sas_uncorrected_baseline.begin(); it != sas_uncorrected_baseline.end(); ) {
        if ((uint32_t)(it->first >> 32) == idx) it = sas_uncorrected_baseline.erase(it);
        else ++it;
    }
}

void AgentxCache::clear() {
    devices.clear();
    nvme_health.clear();        nvme_selftests.clear();
    nvme_controllers.clear();   nvme_namespaces.clear();
    nvme_error_log.clear();     nvme_capabilities.clear();
    nvme_power_states.clear();  nvme_lba_formats.clear();
    sata_attrs.clear();         sata_selftests.clear();
    sata_info.clear();          sata_health.clear();
    sata_error_log.clear();     sata_error_cmds.clear();
    sata_erc.clear();           sata_phy_events.clear();
    sata_selective_tests.clear(); sata_pending_defects.clear();
    sata_log_dir.clear();
    sata_dev_stats.clear();
    sas_health.clear();         sas_error_counters.clear();
    sas_selftests.clear();      sas_info.clear();
    sas_bgscan.clear();         sensors.clear();
    ts_device_table = ts_nvme_controller = ts_nvme_namespace   = {};
    ts_nvme_health  = ts_nvme_selftest   = ts_nvme_error_log   = {};
    ts_nvme_capability = ts_nvme_power_state = ts_nvme_lba_format = {};
    ts_sata_info    = ts_sata_health     = ts_sata_attr         = {};
    ts_sata_error_log = ts_sata_error_cmd = ts_sata_selftest    = {};
    ts_sata_erc = ts_sata_phy_event = ts_sata_selective_test   = {};
    ts_sata_pending_defects = ts_sata_log_dir = ts_sata_dev_stat = {};
    ts_sas_info     = ts_sas_health      = ts_sas_error_counter  = {};
    ts_sas_selftest = ts_sas_bgscan      = ts_sensor             = {};
    hash_sata_by_dev.clear();   ts_sata_by_dev.clear();
    hash_sata_devstat_by_page.clear();   ts_sata_devstat_by_page.clear();
    sata_subidx_unique.clear();
    sensor_alarm_state.clear();   sensor_alarm_last_sent.clear();
    sata_attr_alarm.clear();      sas_uncorrected_baseline.clear();
    next_device_index = 1;
}

void AgentxCache::rebuild_sata_subidx_unique(uint32_t dev_idx) {
    sata_subidx_unique.erase(
        std::remove_if(sata_subidx_unique.begin(), sata_subidx_unique.end(),
                       [dev_idx](const SataSubidxUniqueRow &r) {
                           return r.device_index == dev_idx;
                       }),
        sata_subidx_unique.end());

    std::unordered_set<uint32_t> seen;
    for (const auto &r : sata_error_cmds) {
        if (r.device_index != dev_idx) continue;
        if (seen.insert(r.error_entry_index).second)
            sata_subidx_unique.push_back({dev_idx, 5, r.error_entry_index});
    }
    seen.clear();
    for (const auto &r : sata_dev_stats) {
        if (r.device_index != dev_idx) continue;
        if (seen.insert(r.page_num).second)
            sata_subidx_unique.push_back({dev_idx, 11, r.page_num});
    }
}

const CacheDeviceRow *AgentxCache::find_device(uint32_t idx) const {
    for (const auto &d : devices)
        if (d.index == idx) return &d;
    return nullptr;
}

uint32_t AgentxCache::upsert_device(const std::string &path, DeviceProto proto,
                                    uint32_t hint_idx) {
    for (auto &row : devices) {
        if (row.path == path) {
            row.proto = proto;
            return row.index;
        }
    }
    // Resolve collisions: if hint_idx is taken by a different path, increment.
    uint32_t idx = hint_idx ? hint_idx : next_device_index++;
    for (;;) {
        if (idx == 0) { ++idx; continue; }
        bool taken = false;
        for (const auto &r : devices)
            if (r.index == idx) { taken = true; break; }
        if (!taken) break;
        ++idx;
    }
    CacheDeviceRow row;
    row.index = idx;
    row.path  = path;
    row.proto = proto;
    devices.push_back(row);
    return row.index;
}
