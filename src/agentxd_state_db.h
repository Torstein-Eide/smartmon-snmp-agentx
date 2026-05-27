// agentxd_state_db.h — SQLite-backed persistence for table change timestamps

#pragma once

#include <cstdint>
#include <ctime>
#include <string>

// Open (or create) the state database at path. Empty path disables persistence.
// Returns false on failure (non-fatal; timestamps still work within a run).
bool state_db_open(const std::string &path);

// Load persisted (hash, ts) pairs into g_cache.table_hashes[] and ts_* fields.
// Call once after state_db_open, before the first parse cycle.
void state_db_load();

// Persist one table's hash and timestamp. Called when a table's hash changes.
void state_db_update(int table_id, uint64_t hash, time_t ts);

// Close the database.
void state_db_close();
