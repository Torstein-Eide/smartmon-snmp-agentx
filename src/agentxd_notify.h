// agentxd_notify.h — SNMP v2 trap (NOTIFICATION) wrappers

#pragma once

#include "agentxd_cache.h"

#include <cstdint>
#include <string>

// Health-change notifications (Common + per-protocol)
void notify_device_health_changed(uint32_t dev_idx, int new_status);

// Poll-failure notification (Common MIB)
void notify_device_polling_failed(uint32_t dev_idx, int poll_result);

// Self-test failure notifications (per-protocol, MIB-correct varbinds)
void notify_nvme_selftest_failed(uint32_t dev_idx, const CacheNvmeSelfTestRow &st);
void notify_sata_selftest_failed(uint32_t dev_idx, const CacheSataSelfTestRow &st);
void notify_sas_selftest_failed(uint32_t dev_idx, const CacheSasSelfTestRow &st);

// Device lifecycle notifications (Common MIB)
void notify_device_discovered(uint32_t dev_idx);
// name/path passed explicitly because the cache row may already be erased
void notify_device_removed(uint32_t dev_idx, const std::string &name,
                           const std::string &path, int dev_type);

// SATA prefailure attribute threshold crossed
void notify_sata_attr_failing(uint32_t dev_idx, const CacheSataAttrRow &attr);

// SAS uncorrected error count increased
void notify_sas_uncorrected_errors_increased(uint32_t dev_idx,
                                             const CacheSasErrorCounterRow &row);

// Sensor threshold/state notifications (Sensor MIB)
void notify_sensor_high_critical(uint32_t dev_idx, const CacheSensorRow &sensor);
void notify_sensor_high_warning(uint32_t dev_idx, const CacheSensorRow &sensor);
void notify_sensor_low_warning(uint32_t dev_idx, const CacheSensorRow &sensor);
void notify_sensor_low_critical(uint32_t dev_idx, const CacheSensorRow &sensor);
void notify_sensor_recovered(uint32_t dev_idx, const CacheSensorRow &sensor);
