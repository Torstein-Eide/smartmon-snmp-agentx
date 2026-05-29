// agentxd_state_db.h — SQLite-backed persistence for table change timestamps

#pragma once

#include <cstdint>
#include <ctime>
#include <string>

// Open (or create) the state database at path. Empty path disables persistence.
// Returns false on failure (non-fatal; timestamps still work within a run).
bool state_db_open(const std::string &path);

// Load persisted state into g_cache. Call once after state_db_open, before first parse.
void state_db_load();

// Persist one global table's hash and timestamp. Called when a table's hash changes.
void state_db_update(int table_id, uint64_t hash, time_t ts);

// Persist one per-(device, tableId) ByDevice entry. Called when its hash changes.
void state_db_update_by_dev(uint32_t dev_id, uint32_t table_id, uint64_t hash, time_t ts);

// Persist one per-page devstat BySubindex entry. Called when the page's hash changes.
void state_db_update_devstat_page(uint32_t dev_id, uint32_t page_num,
                                  uint64_t hash, time_t ts);

// Remove all persisted per-device and per-row entries for a device.
void state_db_remove_device(uint32_t dev_id);

// Persist sensor alarm state for one (device, sensor) pair.
void state_db_update_sensor_alarm(uint32_t dev_id, uint32_t sensor_idx,
                                  int alarm_state, time_t last_sent);

// Add or remove one SATA attribute from the persisted failing-attribute set.
void state_db_set_sata_attr_alarm(uint32_t dev_id, uint32_t attr_id, bool failing);

// Persist the SAS uncorrected error baseline for one (device, direction) pair.
void state_db_update_sas_uncorrected_baseline(uint32_t dev_id, int direction,
                                              uint64_t uncorrected);

// Persist SATA self-test in-progress state (updated only on falling edge of remaining_pct).
void state_db_update_selftest_progress(uint32_t dev_id, uint64_t start_ns,
                                       uint32_t last_remaining, uint32_t polling_min,
                                       time_t estimated_completion);
void state_db_clear_selftest_progress(uint32_t dev_id);

// Close the database.
void state_db_close();
