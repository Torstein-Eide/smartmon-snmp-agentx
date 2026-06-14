# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Two implementations — know which branch you are on

This repo holds **two implementations of the same SNMP AgentX subagent**, on
different branches:

- **`master`** — the original C++ daemon (`smartmon-snmp-agentxd`); source in
  `src/*.cpp`, built with the top-level `Makefile` (`/build-make`).
- **`python`** (this branch) — a single self-contained Python script,
  `smartmon_agentx.py`, that is the active line of development.

On the `python` branch there is **no `src/` tree**. The top-level `Makefile`,
`tests/Makefile`, and `tests/test_*.cpp` are carried over from `master` and
reference `src/` files that do not exist here — do **not** run `make` / `make
test` on this branch; they will fail. Everything below describes the Python
agent. The MIB sources (`doc/*.mib`), the CI harness (`ci/`), the SNMP fixtures
(`tests/fixtures/`, `tests/fixture-variants/`), the systemd units, and the
install scripts are shared with `master`.

## Versioning

The agent's version is `VERSION` near the top of `smartmon_agentx.py` (surfaced
via `--version` and the systemd `STATUS=` line).

**On every change to `smartmon_agentx.py`, bump the patch component** (e.g.
`0.1.2` → `0.1.3`). Minor for notable features, major for breaking/MIB-incompatible
changes; otherwise default to a patch bump.

## Running and testing

There is no build step — the script carries a `#!/usr/bin/env python3` shebang.
It requires the `python3-netsnmpagent` module (SQLite persistence uses the stdlib).

**Run the agent directly:**
```bash
# File mode against a directory of smartd --jsonstate JSON files, foreground
./smartmon_agentx.py -f --state-dir /run/smartmontools/json --log-level INFO

# Collect mode (polls smartctl directly; needs root or sudo -n smartctl)
sudo ./smartmon_agentx.py -f --collect --log-level INFO

# One-shot smoke test (collect/build/publish once, then exit)
./smartmon_agentx.py --once --state-dir /run/smartmontools/json
```

`--log-level DEBUG-AGENTX` is `DEBUG` plus raw net-snmp AgentX PDU tracing.

**Live SNMP integration test** (starts a private `snmpd` on `127.0.0.1`, no root
needed; requires `snmpd` + `python3-netsnmpagent`):
```bash
AGENTXD_BIN=smartmon_agentx.py ci/run_integration_test.py
# Run only matching sections (substring match against integration_test.yaml):
AGENTXD_BIN=smartmon_agentx.py ci/run_integration_test.py --section nvme
```

**Full integration test in Docker** (builds `ci/Dockerfile.agentx_py` with the
net-snmp Python bindings — use this for a clean, reproducible run):
```bash
ci/run_docker_py.sh
```

**File range reads in Bash** — use `head | tail`, not `sed -n`:
```bash
head -n 160 smartmon_agentx.py | tail -n +125
```

## Architecture

`smartmon_agentx.py` connects to a running `snmpd` master over the AgentX Unix
socket, registers the SMARTMON-* OID subtrees, answers GET/GETNEXT/GETBULK, and
sends v2 traps. It obtains SMART data two ways:

- **collect mode** (`collect: true` / `--collect`): polls `smartctl` directly
  (as root, or via `sudo -n smartctl` when unprivileged). No `state_dir`.
  Discovery is event-driven via a `udevadm monitor` thread on block hotplug.
- **file mode** (default): reads `smartctl --jsonstate` JSON files from
  `state_dir`, re-stat'd each poll for changes.

### Producer/consumer threading model

net-snmp is **not thread-safe**, so socket access is confined to one thread:

- **Main thread** — the only net-snmp caller. Registers scalars/tables, answers
  SNMP, and runs the select loop. It pops rebuilt OID snapshots off `_publish_q`
  and publishes them, and pops trap descriptors off `_notify_q` and sends them.
  It polls at `NOTIFY_POLL_INTERVAL` (0.05s) so worker-detected traps go out
  promptly even with no client traffic.
- **Collector thread** (`_collector_loop`) — owns **all** data collection and
  `_st` mutation. Every `_st.ttl` seconds (`cache_timeout`, default 30) it runs
  `_refresh()` (discover → parse → `_build`), which is pure Python + file IO and
  touches no net-snmp. It enqueues trap descriptors onto `_notify_q` and the
  rebuilt `oid_map` onto `_publish_q`. Woken early by `_refresh_request`.
- **udev thread** (`_udev_monitor_loop`, collect mode only) — watches block
  hotplug and sets `_rescan_event` + `_refresh_request` to trigger a rescan.

`_State` (global `_st`) holds runtime config and the cached parsed data;
`_publish_q`, `_notify_q`, `_refresh_request`, `_rescan_event`, `_status_event`
are the cross-thread channels.

### OID map and the `_build` pipeline

`_build(devices, ts, ...)` is the core: it takes parsed device dicts and
produces a flat `oid_map` (`{full_oid_tuple: (snmp_type, value)}`) covering every
scalar and table cell. Helpers `_parse_nvme_health`, `_parse_sata_info`,
`_parse_sata_attrs`, `_parse_sas_*`, etc. turn raw `smartctl` JSON into the dicts
`_build` consumes. The main thread's `_publish_*` functions diff this map against
the registered net-snmp scalars/tables and update only what changed.

`_build` also does **change detection**: it hashes each table's SNMP-visible
contents and advances that table's `LastChange` timestamp only when the contents
actually change (so ordinary polling does not look like a change to managers),
and it enqueues the appropriate trap descriptors onto `_notify_q`.

### State persistence

Optional SQLite DB (`state_db` / `--state-db`) persists table-change timestamps
and notification baselines across restarts. It is opened and `state_db_load()`'d
**before** the first `_build` so loaded hashes match current data (timestamps are
preserved, not advanced) and a restart does not emit a trap storm.

### systemd integration

The unit is `Type=notify`. The agent implements sd_notify: `READY=1` after the
first publish, a `STATUS=` line (`_sd_status_text`), and `WATCHDOG=1` pings.
Collect mode requires the unit's `RestrictAddressFamilies` to include
`AF_NETLINK` (for `udevadm monitor`) — otherwise udevadm exits instantly and the
monitor thread respawns it in a loop (after 3 fast exits it falls back to
per-poll discovery).

## OID layout

Enterprise prefix `1.3.6.1.4.1.65891.1.1` (placeholder PEN):

| Suffix | MIB | Contents |
|--------|-----|----------|
| `.1` | SMARTMON-TC-MIB | Textual conventions |
| `.2` | SMARTMON-COMMON-MIB | Device inventory, counts, poll status |
| `.3` | SMARTMON-NVME-MIB | NVMe health, self-test, controller, namespace, error log |
| `.4` | SMARTMON-SATA-MIB | SATA attributes, self-test, info, health, error log |
| `.5` | SMARTMON-SAS-MIB | SAS health, error counters, self-test (partial) |
| `.6` | SMARTMON-SENSOR-MIB | Unified sensor table + threshold notifications |

MIB sources are in `doc/*.mib`, installed to `/usr/share/snmp/mibs/`.

## Integration tests

Driven by `ci/integration_test.yaml` via `ci/run_integration_test.py`. Each
`sections` entry specifies a walk subtree plus per-OID expected values;
`notifications` entries swap in a variant fixture and assert a trap is delivered.
Fixtures live in `tests/fixtures/`; **variant fixtures for notification tests
must go in `tests/fixture-variants/`, not `fixtures/`** (the harness treats every
file in `fixtures/` as a steady-state device).

### SNMP output quirks (for expected values in `integration_test.yaml`)

- Empty strings have **no** `STRING:` prefix — match with `'""'`; never write
  `STRING: ""`.
- `Hex-STRING` / `BITS` values have a **trailing space** — for an 8-byte
  `DateAndTime` use `'Hex-STRING: ([0-9A-F]{2} ){8}'`.

## Net-snmp sub-identifier limit

GETNEXT silently drops table rows whose index sub-id is ≥ 2^31. Any hashed index
(e.g. FNV table hashes) **must be masked to 31 bits** or those rows become
invisible to walks.
