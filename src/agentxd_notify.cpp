// agentxd_notify.cpp - SNMP v2 trap sender

#include "agentxd_notify.h"
#include "agentxd_cache.h"
#include "agentxd_config.h"
#include "snmp_oids.h"

#include <cstring>
#include <ctime>
#include <syslog.h>
#include <vector>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void send_v2trap_timed(netsnmp_variable_list *vars, const char *trap_name) {
    syslog(LOG_DEBUG, "notify: sending trap %s", trap_name);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    send_v2trap(vars);
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    if (ms >= 10)
        syslog(LOG_WARNING, "notify: send_v2trap(%s) took %ldms", trap_name, ms);
    else
        syslog(LOG_DEBUG, "notify: send_v2trap(%s) took %ldms", trap_name, ms);
}

static netsnmp_variable_list *
make_trap_header(const oid *trap_oid, size_t trap_oid_len) {
    netsnmp_variable_list *vars = nullptr;
    oid snmptrapoid[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
    size_t snmptrapoid_len = sizeof(snmptrapoid) / sizeof(snmptrapoid[0]);
    snmp_varlist_add_variable(&vars,
        snmptrapoid, snmptrapoid_len,
        ASN_OBJECT_ID,
        (u_char*)trap_oid, trap_oid_len * sizeof(oid));
    return vars;
}

static void append_uint32(netsnmp_variable_list **vars,
                          const oid *col_oid, size_t col_len,
                          uint32_t instance_idx,
                          u_char asn_type, u_long value) {
    std::vector<oid> inst(col_len + 1);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)instance_idx;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                              asn_type, (u_char*)&value, sizeof(value));
}

static void append_string(netsnmp_variable_list **vars,
                          const oid *col_oid, size_t col_len,
                          uint32_t instance_idx,
                          const char *str) {
    std::vector<oid> inst(col_len + 1);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)instance_idx;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                              ASN_OCTET_STR,
                              (u_char*)str, strlen(str));
}

static void append_uint32_2idx(netsnmp_variable_list **vars,
                               const oid *col_oid, size_t col_len,
                               uint32_t idx1, uint32_t idx2,
                               u_char asn_type, u_long value) {
    std::vector<oid> inst(col_len + 2);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)idx1;
    inst[col_len + 1] = (oid)idx2;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                              asn_type, (u_char*)&value, sizeof(value));
}

static void append_int32_2idx(netsnmp_variable_list **vars,
                              const oid *col_oid, size_t col_len,
                              uint32_t idx1, uint32_t idx2,
                              int32_t value) {
    long v = value;
    std::vector<oid> inst(col_len + 2);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)idx1;
    inst[col_len + 1] = (oid)idx2;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                              ASN_INTEGER, (u_char*)&v, sizeof(v));
}

static void append_string_2idx(netsnmp_variable_list **vars,
                               const oid *col_oid, size_t col_len,
                               uint32_t idx1, uint32_t idx2,
                               const char *str) {
    std::vector<oid> inst(col_len + 2);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)idx1;
    inst[col_len + 1] = (oid)idx2;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                              ASN_OCTET_STR,
                              (u_char*)str, strlen(str));
}

static void append_date_time(netsnmp_variable_list **vars,
                             const oid *col_oid, size_t col_len,
                             uint32_t instance_idx, time_t t) {
    uint8_t dt[11];
    snmp_encode_date_time({t, 0}, dt);
    std::vector<oid> inst(col_len + 1);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)instance_idx;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                              ASN_OCTET_STR, dt, sizeof(dt));
}

static void append_counter64_2idx(netsnmp_variable_list **vars,
                                   const oid *col_oid, size_t col_len,
                                   uint32_t idx1, uint32_t idx2,
                                  uint64_t value) {
    struct counter64 c64;
    c64.high = (u_long)(value >> 32);
    c64.low = (u_long)(value & 0xffffffffULL);
    std::vector<oid> inst(col_len + 2);
    memcpy(inst.data(), col_oid, col_len * sizeof(oid));
    inst[col_len] = (oid)idx1;
    inst[col_len + 1] = (oid)idx2;
    snmp_varlist_add_variable(vars, inst.data(), inst.size(),
                               ASN_COUNTER64, (u_char*)&c64, sizeof(c64));
}

static void append_device_path(netsnmp_variable_list **vars,
                               uint32_t dev_idx,
                               const CacheDeviceRow *dev) {
    if (!dev)
        return;
    append_string(vars, oid_device_path, OID_LEN(oid_device_path),
                  dev_idx, dev->path.c_str());
}

static void append_device_identity(netsnmp_variable_list **vars,
                                   uint32_t dev_idx,
                                   const CacheDeviceRow *dev) {
    if (!dev)
        return;
    append_string(vars, oid_device_name, OID_LEN(oid_device_name),
                  dev_idx, dev->name.c_str());
    append_device_path(vars, dev_idx, dev);
}

static void append_nvme_identity(netsnmp_variable_list **vars,
                                 uint32_t dev_idx,
                                 const CacheDeviceRow *dev) {
    if (dev) {
        append_string(vars, oid_device_model_name, OID_LEN(oid_device_model_name),
                      dev_idx, dev->model_name.c_str());
        append_string(vars, oid_device_serial_number, OID_LEN(oid_device_serial_number),
                      dev_idx, dev->serial_number.c_str());
    }
    append_device_path(vars, dev_idx, dev);
}

static void append_sata_identity(netsnmp_variable_list **vars,
                                 uint32_t dev_idx,
                                 const CacheDeviceRow *dev) {
    if (dev) {
        append_string(vars, oid_device_model_name, OID_LEN(oid_device_model_name),
                      dev_idx, dev->model_name.c_str());
        append_string(vars, oid_device_serial_number, OID_LEN(oid_device_serial_number),
                      dev_idx, dev->serial_number.c_str());
    }
    append_device_path(vars, dev_idx, dev);
}

static void append_sas_identity(netsnmp_variable_list **vars,
                                uint32_t dev_idx,
                                const CacheDeviceRow *dev) {
    if (dev) {
        append_string(vars, oid_device_model_name, OID_LEN(oid_device_model_name),
                      dev_idx, dev->model_name.c_str());
        append_string(vars, oid_device_serial_number, OID_LEN(oid_device_serial_number),
                      dev_idx, dev->serial_number.c_str());
    }
    append_device_path(vars, dev_idx, dev);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void notify_device_health_changed(uint32_t dev_idx, int new_status) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: health_changed dev_idx=%u path=%s status=%d",
           dev_idx, dev ? dev->path.c_str() : "(unknown)", new_status);

    const oid *notif_oid = oid_notif_nvme_health_changed;
    size_t notif_len = OID_LEN(oid_notif_nvme_health_changed);
    if (dev) {
        if (dev->proto == PROTO_ATA || dev->proto == PROTO_SAT) {
            notif_oid = oid_notif_sata_health_degraded;
            notif_len = OID_LEN(oid_notif_sata_health_degraded);
        } else if (dev->proto == PROTO_SCSI || dev->proto == PROTO_SAS) {
            notif_oid = oid_notif_sas_health_changed;
            notif_len = OID_LEN(oid_notif_sas_health_changed);
        }
    }

    netsnmp_variable_list *vars = make_trap_header(notif_oid, notif_len);

    if (dev) {
        if (dev->proto == PROTO_NVME) {
            append_nvme_identity(&vars, dev_idx, dev);
            append_uint32_2idx(&vars,
                oid_nvme_health_status, OID_LEN(oid_nvme_health_status),
                dev_idx, 1, ASN_INTEGER, (u_long)new_status);
            for (const auto &h : g_cache.nvme_health) {
                if (h.device_index != dev_idx)
                    continue;
                std::vector<oid> inst(OID_LEN(oid_nvme_critical_warning) + 2);
                memcpy(inst.data(), oid_nvme_critical_warning,
                       OID_LEN(oid_nvme_critical_warning) * sizeof(oid));
                inst[OID_LEN(oid_nvme_critical_warning)] = (oid)dev_idx;
                inst[OID_LEN(oid_nvme_critical_warning) + 1] = (oid)1;
                snmp_varlist_add_variable(&vars, inst.data(), inst.size(),
                    ASN_OCTET_STR, &h.critical_warning, 1);
                break;
            }
        } else if (dev->proto == PROTO_ATA || dev->proto == PROTO_SAT) {
            append_sata_identity(&vars, dev_idx, dev);
            append_uint32_2idx(&vars,
                oid_sata_health_status, OID_LEN(oid_sata_health_status),
                dev_idx, 1, ASN_INTEGER, (u_long)new_status);
        } else if (dev->proto == PROTO_SCSI || dev->proto == PROTO_SAS) {
            append_sas_identity(&vars, dev_idx, dev);
            append_uint32_2idx(&vars,
                oid_sas_health_status, OID_LEN(oid_sas_health_status),
                dev_idx, 1, ASN_INTEGER, (u_long)new_status);
        }
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);
    }

    send_v2trap_timed(vars, "health_changed");
    snmp_free_varbind(vars);
}

void notify_device_polling_failed(uint32_t dev_idx, int poll_result) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: polling_failed dev_idx=%u path=%s poll_result=%d exit_status=%u",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           poll_result, dev ? dev->poll_exit_status : 0u);

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_device_poll_failed,
                         OID_LEN(oid_notif_device_poll_failed));
    append_device_identity(&vars, dev_idx, dev);
    append_uint32(&vars, oid_device_last_poll_result,
                  OID_LEN(oid_device_last_poll_result),
                  dev_idx, ASN_INTEGER, (u_long)poll_result);
    if (dev) {
        append_uint32(&vars, oid_device_poll_exit_status,
                      OID_LEN(oid_device_poll_exit_status),
                      dev_idx, ASN_UNSIGNED, (u_long)dev->poll_exit_status);
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);
    }

    append_uint32(&vars, oid_poll_failure_threshold,
                  OID_LEN(oid_poll_failure_threshold),
                  0, ASN_UNSIGNED, (u_long)g_poll_failure_threshold);
    send_v2trap_timed(vars, "polling_failed");
    snmp_free_varbind(vars);
}

void notify_nvme_selftest_failed(uint32_t dev_idx, const CacheNvmeSelfTestRow &st) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: nvme_selftest_failed dev_idx=%u path=%s entry=%u type=%u result=%u (%s)",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           st.entry_index, st.type, st.result, st.result_text.c_str());

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_nvme_selftest_failed,
                         OID_LEN(oid_notif_nvme_selftest_failed));
    append_nvme_identity(&vars, dev_idx, dev);

    uint32_t entry = st.entry_index;
    append_uint32_2idx(&vars, oid_nvme_selftest_number,
                       OID_LEN(oid_nvme_selftest_number),
                       dev_idx, entry, ASN_UNSIGNED, (u_long)st.number);
    append_uint32_2idx(&vars, oid_nvme_selftest_type,
                       OID_LEN(oid_nvme_selftest_type),
                       dev_idx, entry, ASN_INTEGER, (u_long)st.type);
    append_uint32_2idx(&vars, oid_nvme_selftest_result,
                       OID_LEN(oid_nvme_selftest_result),
                       dev_idx, entry, ASN_INTEGER, (u_long)st.result);
    append_string_2idx(&vars, oid_nvme_selftest_result_text,
                       OID_LEN(oid_nvme_selftest_result_text),
                       dev_idx, entry, st.result_text.c_str());
    if (dev)
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);

    send_v2trap_timed(vars, "nvme_selftest_failed");
    snmp_free_varbind(vars);
}

void notify_sata_selftest_failed(uint32_t dev_idx, const CacheSataSelfTestRow &st) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: sata_selftest_failed dev_idx=%u path=%s entry=%u type=%u result=%u",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           st.entry_index, st.type, st.result);

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_sata_selftest_failed,
                         OID_LEN(oid_notif_sata_selftest_failed));
    append_sata_identity(&vars, dev_idx, dev);

    uint32_t entry = st.entry_index;
    append_uint32_2idx(&vars, oid_sata_selftest_type,
                       OID_LEN(oid_sata_selftest_type),
                       dev_idx, entry, ASN_INTEGER, (u_long)st.type);
    append_uint32_2idx(&vars, oid_sata_selftest_result,
                       OID_LEN(oid_sata_selftest_result),
                       dev_idx, entry, ASN_INTEGER, (u_long)st.result);
    if (dev)
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);

    send_v2trap_timed(vars, "sata_selftest_failed");
    snmp_free_varbind(vars);
}

void notify_sas_selftest_failed(uint32_t dev_idx, const CacheSasSelfTestRow &st) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: sas_selftest_failed dev_idx=%u path=%s entry=%u type=%u result=%u (%s)",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           st.entry_index, st.type, st.result, st.result_str.c_str());

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_sas_selftest_failed,
                         OID_LEN(oid_notif_sas_selftest_failed));
    append_sas_identity(&vars, dev_idx, dev);

    uint32_t entry = st.entry_index;
    append_uint32_2idx(&vars, oid_sas_selftest_type,
                       OID_LEN(oid_sas_selftest_type),
                       dev_idx, entry, ASN_INTEGER, (u_long)st.type);
    append_uint32_2idx(&vars, oid_sas_selftest_result,
                       OID_LEN(oid_sas_selftest_result),
                       dev_idx, entry, ASN_INTEGER, (u_long)st.result);
    append_string_2idx(&vars, oid_sas_selftest_result_str,
                       OID_LEN(oid_sas_selftest_result_str),
                       dev_idx, entry, st.result_str.c_str());
    if (dev)
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);

    send_v2trap_timed(vars, "sas_selftest_failed");
    snmp_free_varbind(vars);
}

void notify_device_discovered(uint32_t dev_idx) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: device_discovered dev_idx=%u path=%s name=%s type=%d",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           dev ? dev->name.c_str() : "(unknown)", dev ? (int)dev->proto : -1);

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_device_discovered,
                         OID_LEN(oid_notif_device_discovered));
    append_device_identity(&vars, dev_idx, dev);
    if (dev) {
        append_uint32(&vars, oid_device_type, OID_LEN(oid_device_type),
                      dev_idx, ASN_INTEGER, (u_long)dev->proto);
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);
    }

    send_v2trap_timed(vars, "device_discovered");
    snmp_free_varbind(vars);
}

void notify_device_removed(uint32_t dev_idx, const std::string &name,
                           const std::string &path, int dev_type) {
    syslog(LOG_INFO, "notify: device_removed dev_idx=%u path=%s name=%s type=%d",
           dev_idx, path.c_str(), name.c_str(), dev_type);

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_device_removed,
                         OID_LEN(oid_notif_device_removed));

    append_string(&vars, oid_device_name, OID_LEN(oid_device_name),
                  dev_idx, name.c_str());
    append_string(&vars, oid_device_path, OID_LEN(oid_device_path),
                  dev_idx, path.c_str());
    append_uint32(&vars, oid_device_type, OID_LEN(oid_device_type),
                  dev_idx, ASN_INTEGER, (u_long)dev_type);

    send_v2trap_timed(vars, "device_removed");
    snmp_free_varbind(vars);
}

void notify_sata_attr_failing(uint32_t dev_idx, const CacheSataAttrRow &attr) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: sata_attr_failing dev_idx=%u path=%s attr_id=%u name=%s value=%u threshold=%u",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           attr.attr_id, attr.name.c_str(), attr.value, attr.threshold);

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_sata_attr_threshold_met,
                         OID_LEN(oid_notif_sata_attr_threshold_met));
    append_sata_identity(&vars, dev_idx, dev);

    uint32_t attr_id = attr.attr_id;
    append_uint32_2idx(&vars, oid_sata_attr_id,
                       OID_LEN(oid_sata_attr_id),
                       dev_idx, attr_id, ASN_UNSIGNED, (u_long)attr_id);
    append_string_2idx(&vars, oid_sata_attr_name,
                       OID_LEN(oid_sata_attr_name),
                       dev_idx, attr_id, attr.name.c_str());
    append_uint32_2idx(&vars, oid_sata_attr_value,
                       OID_LEN(oid_sata_attr_value),
                       dev_idx, attr_id, ASN_GAUGE, (u_long)attr.value);
    append_uint32_2idx(&vars, oid_sata_attr_threshold,
                       OID_LEN(oid_sata_attr_threshold),
                       dev_idx, attr_id, ASN_GAUGE, (u_long)attr.threshold);
    if (dev)
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);

    send_v2trap_timed(vars, "sata_attr_failing");
    snmp_free_varbind(vars);
}

void notify_sas_uncorrected_errors_increased(uint32_t dev_idx,
                                             const CacheSasErrorCounterRow &ec) {
    const CacheDeviceRow *dev = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: sas_uncorrected_errors dev_idx=%u path=%s direction=%d uncorrected=%llu",
           dev_idx, dev ? dev->path.c_str() : "(unknown)",
           ec.direction, (unsigned long long)ec.uncorrected);

    netsnmp_variable_list *vars =
        make_trap_header(oid_notif_sas_uncorrected_errors,
                         OID_LEN(oid_notif_sas_uncorrected_errors));
    append_sas_identity(&vars, dev_idx, dev);

    uint32_t dir = (uint32_t)ec.direction;
    append_counter64_2idx(&vars, oid_sas_uncorrected_errors,
                          OID_LEN(oid_sas_uncorrected_errors),
                          dev_idx, dir, ec.uncorrected);
    if (dev)
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev->last_poll_time);

    send_v2trap_timed(vars, "sas_uncorrected_errors");
    snmp_free_varbind(vars);
}

static void notify_sensor_threshold(uint32_t dev_idx, const CacheSensorRow &sensor,
                                    const oid *notif_oid, size_t notif_len,
                                    const oid *threshold_oid, size_t threshold_len,
                                    int32_t threshold_value,
                                    const char *trap_name) {
    const CacheDeviceRow *dev_log = g_cache.find_device(dev_idx);
    syslog(LOG_INFO, "notify: %s dev_idx=%u path=%s sensor=%s value=%d threshold=%d",
           trap_name, dev_idx, dev_log ? dev_log->path.c_str() : "(unknown)",
           sensor.name.c_str(), sensor.value, threshold_value);

    netsnmp_variable_list *vars = make_trap_header(notif_oid, notif_len);

    append_device_identity(&vars, dev_idx, dev_log);

    uint32_t sensor_idx = sensor.sensor_index;
    append_string_2idx(&vars, oid_sensor_name, OID_LEN(oid_sensor_name),
                       dev_idx, sensor_idx, sensor.name.c_str());
    append_uint32_2idx(&vars, oid_sensor_type, OID_LEN(oid_sensor_type),
                       dev_idx, sensor_idx, ASN_INTEGER, (u_long)sensor.type);
    append_int32_2idx(&vars, oid_sensor_value, OID_LEN(oid_sensor_value),
                      dev_idx, sensor_idx, sensor.value);
    append_int32_2idx(&vars, threshold_oid, threshold_len,
                      dev_idx, sensor_idx, threshold_value);
    append_string_2idx(&vars, oid_sensor_units, OID_LEN(oid_sensor_units),
                       dev_idx, sensor_idx, sensor.units_display.c_str());
    if (dev_log)
        append_date_time(&vars, oid_device_last_poll_time,
                         OID_LEN(oid_device_last_poll_time),
                         dev_idx, dev_log->last_poll_time);

    send_v2trap_timed(vars, trap_name);
    snmp_free_varbind(vars);
}

void notify_sensor_high_critical(uint32_t dev_idx, const CacheSensorRow &sensor) {
    notify_sensor_threshold(dev_idx, sensor,
        oid_notif_sensor_high_critical, OID_LEN(oid_notif_sensor_high_critical),
        oid_sensor_high_critical, OID_LEN(oid_sensor_high_critical),
        sensor.high_critical, "sensor_high_critical");
}

void notify_sensor_high_warning(uint32_t dev_idx, const CacheSensorRow &sensor) {
    notify_sensor_threshold(dev_idx, sensor,
        oid_notif_sensor_high_warning, OID_LEN(oid_notif_sensor_high_warning),
        oid_sensor_high_warning, OID_LEN(oid_sensor_high_warning),
        sensor.high_warning, "sensor_high_warning");
}

void notify_sensor_low_warning(uint32_t dev_idx, const CacheSensorRow &sensor) {
    notify_sensor_threshold(dev_idx, sensor,
        oid_notif_sensor_low_warning, OID_LEN(oid_notif_sensor_low_warning),
        oid_sensor_low_warning, OID_LEN(oid_sensor_low_warning),
        sensor.low_warning, "sensor_low_warning");
}

void notify_sensor_low_critical(uint32_t dev_idx, const CacheSensorRow &sensor) {
    notify_sensor_threshold(dev_idx, sensor,
        oid_notif_sensor_low_critical, OID_LEN(oid_notif_sensor_low_critical),
        oid_sensor_low_critical, OID_LEN(oid_sensor_low_critical),
        sensor.low_critical, "sensor_low_critical");
}
