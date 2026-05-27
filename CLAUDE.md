# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

**Build the daemon:**
```bash
/build-make
```

**Run unit tests:**
```bash
/build-make test
```

**Docker build (full CI, Debian 11):**
```bash
docker build -f Dockerfile.debian11 .
```

**Clang-Tidy (static analysis):**
```bash
clang-tidy src/*.cpp -- $(pkg-config --cflags netsnmp) -std=c++17 -Isrc
```

**Cppcheck:**
```bash
cppcheck --enable=all --std=c++17 --suppress=missingIncludeSystem -Isrc src/
```

**File range reads in Bash** — use `head | tail`, not `sed -n`:
```bash
head -n 160 src/somefile.cpp | tail -n +125
```

## Architecture Overview

C++ SNMP AgentX daemon (`smartmon-snmp-agentxd`) that reads `smartd --jsonstate` JSON files and exposes the data via SNMP using net-snmp's AgentX protocol.

### OID Layout

Enterprise prefix `SMARTMON_ENT = 1.3.6.1.4.1.9999.1.1`:

| Suffix | MIB |
|--------|-----|
| `.2` | Common (device inventory, poll status) |
| `.3` | NVMe |
| `.4` | SATA/ATA |
| `.5` | SAS/SCSI |
| `.6` | Sensor |

All OID constants live in `src/snmp_oids.h`. MIB source files are in `doc/*.mib`.

### Source Structure

- **`agentxd_cache.h/.cpp`** — In-memory cache (`AgentxCache` global `g_cache`). All SNMP handlers read from here; updated only by the datasrc module. Contains `CacheDeviceRow`, `CacheNvmeHealthRow`, `CacheSataInfoRow`, etc. plus per-table `time_t ts_*` timestamps.
- **`agentxd_datasrc.cpp`** — Parses smartd JSON files and populates `g_cache`. inotify-driven; called by the main loop. Contains poll-failure hysteresis (`consec_fail_count` per device, fires trap when count ≥ `g_poll_failure_threshold`).
- **`agentxd_config.h/.cpp`** — Config file parser; populates `AgentxConfig`. Exports `int g_verbosity` and `uint32_t g_poll_failure_threshold` as globals.
- **`agentxd_notify.cpp`** — Builds and sends SNMP v2 traps via `notify_device_*` functions.
- **`agentxd_loop.cpp`** — net-snmp AgentX select loop; calls `register_*_mib()` at startup.
- **`snmp_*_mib.cpp`** — One file per MIB subtree; registers handlers. Each exports a `register_*_mib()` called from the loop.
- **`snmp_mib_helpers.h`** — Key macros:
  - `REG_TABLE_U/UU/UUU` — Register iterator tables with 1/2/3 `ASN_UNSIGNED` index columns
  - `TABLE_ROW_COUNT_HANDLER(name, vector_field)` — Scalar returning `g_cache.vector_field.size()`
  - `TABLE_LAST_CHANGE_HANDLER(name, ts_field)` — Scalar returning `g_cache.ts_field` as `DateAndTime`
  - `register_table_ronly(...)` — Underlying function; use directly for non-standard index counts

### SNMP Table Handler Pattern

Every iterator table has a `get_next` function and a `handler`:

```cpp
// get_next: advance loop_ctx (size_t row index), set data_ctx to row pointer,
// populate put_idx index columns; return nullptr at end.
static netsnmp_variable_list *
foo_get_next(void **loop_ctx, void **data_ctx, netsnmp_variable_list *put_idx, ...) {
    size_t idx = (size_t)(uintptr_t)*loop_ctx;
    if (idx >= g_cache.foo.size()) return nullptr;
    *data_ctx = &g_cache.foo[idx];
    *loop_ctx = (void*)(uintptr_t)(idx + 1);
    // snmp_set_var_value(put_idx, ...) for each index column
    return put_idx;
}
```

**DateAndTime columns:**
```cpp
uint8_t dt[8];
snmp_encode_date_time(row->timestamp, dt);
snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR, dt, sizeof(dt));
```

**Not-instantiated optional columns** (backing `time_t` is 0):
```cpp
case N:
    if (row->estimated_completion == 0) {
        netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
    } else {
        uint8_t dt[8]; snmp_encode_date_time(row->estimated_completion, dt);
        snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR, dt, sizeof(dt));
    } break;
```

**Virtual (computed) rows** — encode everything into the opaque `loop_ctx`/`data_ctx` pointer to avoid allocation:
```cpp
// e.g. ByDevice: step = device_vector_idx * 12 + (table_id - 1)
// in handler: dev = step/12, tid = step%12+1
```

### SATA Change Subtree (`.4.1.2`)

`smartSATAChanges` provides three iterator tables:

- **MetadataTable** (`.4.1.2.1`): 12 rows (one per tracked SATA table); INDEX = `{tableId}`
- **ByDeviceTable** (`.4.1.2.2`): `N_devices × 12` virtual rows; INDEX = `{deviceIndex, tableId}`
- **BySubindexTable** (`.4.1.2.3`): rows from `sata_error_cmds` (tableId=5) + `sata_dev_stats` (tableId=11); INDEX = `{deviceIndex, tableId, sub1, sub2}` — registered inline with a 4-element index array (no macro for 4 indexes)

### Tests

`tests/test_datasrc.cpp` compiles as a single TU by `#include`-ing source files directly. It stubs out `syslog`, net-snmp, and notify functions, and defines `g_verbosity` and `g_poll_failure_threshold` itself. **When adding new globals to `agentxd_config.cpp`, add a matching stub definition in `tests/test_datasrc.cpp`.**

Integration tests live in `ci/integration_test.yaml`, run by `ci/run_integration_test.py`. Each `sections` entry specifies a walk subtree and OID tests; `notifications` entries swap fixture files and verify trap delivery. Fixtures go in `tests/fixtures/`; variant fixtures (for notification tests) go in `tests/fixture-variants/`.

### SNMP Output Quirks (for `integration_test.yaml` expected values)

- Empty strings have no `STRING:` prefix — match with `'""'`
- `Hex-STRING` values have a trailing space — use `'Hex-STRING: ([0-9A-F]{2} ){8}'` for 8-byte `DateAndTime`
- Do not write `STRING: ""` for empty string expected values
