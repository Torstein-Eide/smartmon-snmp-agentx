#!/usr/bin/env python3
# (c) 2026, LibreNMS
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Self-contained AgentX subagent for SMARTMON-*-MIB."""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = 1

VERBOSE = 15
NOTICE  = 25
logging.addLevelName(VERBOSE, "VERBOSE")
logging.addLevelName(NOTICE,  "NOTICE")


def _verbose(self, message, *args, **kws):
    if self.isEnabledFor(VERBOSE):
        self._log(VERBOSE, message, args, **kws)


def _notice(self, message, *args, **kws):
    if self.isEnabledFor(NOTICE):
        self._log(NOTICE, message, args, **kws)


logging.Logger.verbose = _verbose
logging.Logger.notice  = _notice

LOGGER = logging.getLogger("smartmon")
LOG = LOGGER

# --------------------------------------------------------------------------
# SNMP constants
# --------------------------------------------------------------------------

BASE_OID  = (1, 3, 6, 1, 4, 1, 65891, 1, 1)
CACHE_TTL = 300

# net-snmp's table_dataset mishandles Unsigned32 row indexes >= 2^31 during
# GETNEXT: a walk stops after the first such row. Keep every table index
# within the signed-positive 31-bit range so snmpwalk traverses all rows.
INDEX_MAX = 0x7FFFFFFF   # 2^31 - 1
UINT32_MAX = 4294967295  # sentinel for unassigned slot

# --------------------------------------------------------------------------
# Collection error codes
# --------------------------------------------------------------------------

EXIT_SUCCESS            = 0
EXIT_DEPENDENCY_MISSING = 1   # no smartd state files found at all (cleanup)
EXIT_NO_DEVICES         = 2   # state_dir empty or not configured         (cleanup)
EXIT_PERMISSION_DENIED  = 3   # state_dir unreadable                      (skip)
EXIT_CONFIG_ERROR       = 5   # configured device not found               (skip)
EXIT_PARTIAL_FAILURE    = 6   # some devices had parse errors             (data served)

_CLEANUP_CODES = frozenset((EXIT_DEPENDENCY_MISSING, EXIT_NO_DEVICES))


class CollectionError(Exception):
    """A collection failure that maps to a smartmonError code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# Textual Convention enum maps (SMARTMON-*-MIB)
# --------------------------------------------------------------------------

_DEVICE_TYPE = {
    "unknown": 0, "ata": 1, "sat": 2, "scsi": 3,
    "sas": 4, "nvme": 5, "usbbridge": 6, "megaraid": 7,
    "cciss": 8, "areca": 9, "other": 255,
}

_HEALTH_STATUS = {
    "unknown": 0, "passed": 1, "failed": 2, "warning": 3, "unavailable": 4,
}

_POLL_RESULT = {
    "unknown": 0, "ok": 1, "failed": 2, "timeout": 3,
    "permissionDenied": 4, "unsupported": 5, "parseError": 6,
}

_ATTR_TYPE = {"unknown": 0, "prefailure": 1, "oldAge": 2}

_ATTR_UPDATED = {"unknown": 0, "always": 1, "offline": 2}

# SmartmonAtaSmartAttrStatus — notRelevant(-1) needs special handling
_ATTR_STATUS_OK       = 1
_ATTR_STATUS_FAILING  = 2
_ATTR_STATUS_FAILED   = 3

_SAS_ERROR_DIR = {"read": 1, "write": 2, "verify": 3}

_SENSOR_TYPE = {
    "other": 1, "unknown": 2, "celsius": 3, "watts": 4,
    "amperes": 5, "voltsDC": 6, "voltsAC": 7, "vibration": 8,
    "rpm": 9, "percent": 10,
}

_SENSOR_SCALE = {
    "yocto": 1, "zepto": 2, "atto": 3, "femto": 4, "pico": 5,
    "nano": 6, "micro": 7, "milli": 8, "units": 9,
    "kilo": 10, "mega": 11, "giga": 12, "tera": 13,
    "peta": 14, "exa": 15, "zetta": 16, "yotta": 17,
}

_SENSOR_STATUS = {"ok": 1, "unavailable": 2, "nonoperational": 3}

# SmartmonAtaOfflineStatus — bits 6:0 of status byte
_ATA_OFFLINE_STATUS = {0: 0, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6}

# SmartmonAtaSelfTestExecStatus — bits 7:4 (nibble >> 4)
_SELFTEST_EXEC_STATUS = {i: i for i in range(16)}

# ==========================================================================
# Part 1 — Data collection (smartd JSON state files)
# ==========================================================================

def _discover_devices(state_dir: str, config_devices=None) -> List[str]:
    """Return sorted list of smartd JSON state file paths in state_dir.

    Skips *.farm.ata.json supplementary files (Seagate FARM log).
    Raises CollectionError when no files are found."""
    try:
        all_files = glob.glob(os.path.join(state_dir, "*.json"))
    except OSError as exc:
        raise CollectionError(EXIT_PERMISSION_DENIED,
                              f"cannot scan {state_dir!r}: {exc}") from exc

    # Keep only files whose names end with a known protocol suffix;
    # exclude Seagate FARM supplementary logs (.farm.ata.json).
    _PROTO_SUFFIX = re.compile(r'\.(ata|sat|nvme|scsi|sas)\.json$')
    files = [f for f in all_files
             if _PROTO_SUFFIX.search(os.path.basename(f))
             and not f.endswith(".farm.ata.json")]

    if config_devices:
        filtered = []
        for f in files:
            bn = os.path.basename(f)
            for spec in config_devices:
                if str(spec) in bn:
                    filtered.append(f)
                    break
        if not filtered:
            raise CollectionError(EXIT_CONFIG_ERROR,
                                  "configured devices not found in state_dir")
        files = filtered

    if not files:
        raise CollectionError(EXIT_NO_DEVICES,
                              f"no smartd JSON state files found in {state_dir!r}")

    files = sorted(files)
    LOGGER.debug("discovered %d state files in %r", len(files), state_dir)
    return files


def _parse_device_info_string(s: str) -> dict:
    """Parse smartd device_info like 'MODEL, S/N:SN, WWN:w, FW:fw, SIZE'."""
    result: Dict[str, str] = {"model": "", "serial": "", "firmware": "", "wwn": ""}
    if not s:
        return result
    m = re.match(r'^([^,]+?)(?=,\s*S/N:|,|$)', s)
    if m:
        result["model"] = m.group(1).strip()
    m = re.search(r'S/N:(\S+?)(?:,|$)', s)
    if m:
        result["serial"] = m.group(1).rstrip(',')
    m = re.search(r'FW:(\S+?)(?:,|$)', s)
    if m:
        result["firmware"] = m.group(1).rstrip(',')
    m = re.search(r'WWN:([\w-]+)', s)
    if m:
        result["wwn"] = m.group(1)
    return result


def _parse_device_json(path: str) -> dict:
    """Parse a smartd JSON state file; return device dict (read_error=None on success)."""
    result: Dict[str, Any] = {
        "path": path, "name": "", "device_path": "", "protocol": "",
        "device_type": 0, "poll_time": None, "smart_passed": None,
        "model_family": "", "model_name": "", "serial_number": "",
        "firmware_version": "", "wwn": "", "raw": {}, "read_error": None,
    }
    try:
        with open(path) as fh:
            raw = json.load(fh)
        result["raw"] = raw
    except (OSError, json.JSONDecodeError) as exc:
        result["read_error"] = str(exc)
        return result

    device = raw.get("device") or {}
    device_name = device.get("name", "")
    result["device_path"] = device_name
    result["name"] = os.path.basename(device_name)

    # Protocol from device.protocol field; fall back to filename suffix
    proto_str = (device.get("protocol") or "").lower()
    if not proto_str:
        bn = os.path.basename(path)
        m = re.search(r'\.(ata|sat|nvme|scsi|sas)\.json$', bn)
        proto_str = m.group(1) if m else "unknown"

    result["protocol"]    = proto_str
    result["device_type"] = _DEVICE_TYPE.get(proto_str, 0)

    lt = raw.get("local_time") or {}
    ts = lt.get("time_t")
    if ts:
        result["poll_time"] = datetime.fromtimestamp(ts, tz=timezone.utc)

    ss = raw.get("smart_status") or {}
    result["smart_passed"] = ss.get("passed")

    # Identity: top-level fields first
    model_name      = raw.get("model_name") or ""
    serial_number   = raw.get("serial_number") or ""
    firmware_version = raw.get("firmware_version") or ""
    model_family    = raw.get("model_family") or ""
    wwn_raw         = raw.get("wwn")

    # SCSI: build model from scsi_vendor + scsi_product
    if not model_name and raw.get("scsi_product"):
        vendor  = (raw.get("scsi_vendor") or "").strip()
        product = (raw.get("scsi_product") or "").strip()
        model_name = f"{vendor} {product}".strip()
    if not firmware_version:
        firmware_version = (raw.get("scsi_revision") or "").strip()

    # Fall back to device_info string for any remaining missing fields
    if not model_name or not serial_number or wwn_raw is None:
        parsed = _parse_device_info_string(raw.get("device_info") or "")
        if not model_name:
            model_name = parsed["model"]
        if not serial_number:
            serial_number = parsed["serial"]
        if not firmware_version:
            firmware_version = parsed["firmware"]
        if wwn_raw is None and parsed["wwn"]:
            wwn_raw = parsed["wwn"]

    # Format WWN
    wwn = ""
    if isinstance(wwn_raw, dict):
        naa = wwn_raw.get("naa", 0)
        oui = wwn_raw.get("oui", 0)
        wid = wwn_raw.get("id", 0)
        wwn = f"0x{(naa << 60) | (oui << 36) | wid:016x}"
    elif isinstance(wwn_raw, str) and wwn_raw:
        # device_info format "5-000cca-2a4c5b3cb" → remove dashes → hex integer
        hex_str = wwn_raw.replace("-", "")
        try:
            wwn = f"0x{int(hex_str, 16):016x}"
        except ValueError:
            wwn = wwn_raw

    result["model_family"]     = model_family
    result["model_name"]       = model_name
    result["serial_number"]    = serial_number
    result["firmware_version"] = firmware_version
    result["wwn"]              = wwn
    return result


# ==========================================================================
# Part 2 — SNMP type helpers and FNV-1a index assignment
# ==========================================================================

def _truthvalue(b) -> tuple:
    return ("integer", "1" if b else "2")

def _gauge(v) -> tuple:
    return ("gauge", str(int(v) if v is not None else 0))

def _counter64(v) -> tuple:
    return ("counter64", str(int(v) if v is not None else 0))

def _string(v) -> tuple:
    return ("string", "" if v is None else str(v))

def _integer(v) -> tuple:
    return ("integer", str(int(v) if v is not None else 0))

def _encode_datetimeval(dt: datetime) -> bytes:
    """Encode datetime as RFC 2579 DateAndTime (11-byte OCTET STRING with UTC offset)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    offset = dt.utcoffset()
    total_s = int(offset.total_seconds())
    direction = ord('+') if total_s >= 0 else ord('-')
    abs_s = abs(total_s)
    tz_h, tz_m = abs_s // 3600, (abs_s % 3600) // 60
    y = dt.year
    return bytes([
        (y >> 8) & 0xFF, y & 0xFF,
        dt.month, dt.day,
        dt.hour, dt.minute, dt.second,
        dt.microsecond // 100000,
        direction, tz_h, tz_m,
    ])


def _datetimeval(dt: datetime) -> tuple:
    return ("datetimeval", dt)

def _map(table: dict, s) -> int:
    return table.get(str(s).lower().strip(), 0)


def _fnv1a_32(data: bytes) -> int:
    """32-bit FNV-1a hash; always returns a value in 1..4294967294."""
    h = 0x811c9dc5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h or 1


def _probe_index(seed: int, used: set) -> int:
    """Linear-probe for a free 31-bit table index starting from seed."""
    idx = (seed & INDEX_MAX) or 1
    while idx in used:
        idx = (idx % INDEX_MAX) + 1
    return idx


def _device_index(dev: dict, used: set) -> int:
    """Stable 31-bit device index from serial_number|model_name via FNV-1a."""
    seed_str = f"{dev['serial_number']}|{dev['model_name']}"
    seed = _fnv1a_32(seed_str.encode("utf-8", errors="replace"))
    return _probe_index(seed, used)


def _table_fingerprint(entries: list, prefix: tuple) -> int:
    plen = len(prefix)
    parts = sorted(
        f"{typ}\x00{val}"
        for oid, typ, val in entries if oid[:plen] == prefix
    )
    return _fnv1a_32("\x01".join(parts).encode("utf-8", errors="replace"))


# ==========================================================================
# Part 3 — OID table builder (_State, _build)
# ==========================================================================

def _full(suffix: tuple) -> tuple:
    return BASE_OID + suffix


def _oid_str(full: tuple) -> str:
    return "." + ".".join(str(x) for x in full)


class _State:
    oid_keys:       list
    oid_map:        dict
    last_load:      float
    ttl:            int
    checksums:      dict   # table key -> fingerprint int
    timestamps:     dict   # table key -> ISO 8601 string
    state_dir:      str
    config_devices: Optional[list]

    def __init__(self):
        self.oid_keys              = []
        self.oid_map               = {}
        self.last_load             = 0.0
        self.ttl                   = CACHE_TTL
        self.checksums             = {}
        self.timestamps            = {}
        self.state_dir             = ""
        self.config_devices        = None
        self.poll_failure_threshold = 1


_st = _State()

# Table prefix tuples for fingerprinting (full OID prefix of each table entry)
_TABLE_PREFIXES = {
    "device":      _full((2, 1, 3, 1)),
    "nvme_health": _full((3, 1, 15, 1)),
    "sata_health": _full((4, 1, 6, 1)),
    "sata_attr":   _full((4, 1, 9, 1)),
    "sas_health":  _full((5, 1, 6, 1)),
    "sas_err":     _full((5, 1, 9, 1)),
    "sensor":      _full((6, 1, 3, 1)),
}


def _build(devices: list, ts: datetime,
           error_code: int = EXIT_SUCCESS, error_string: str = "") -> None:
    """Rebuild the OID map from a list of parsed device dicts."""
    entries: List[Tuple] = []
    ts_iso = ts.isoformat()

    def add(suffix, typ, val):
        entries.append((_full(suffix), typ, val))

    # Count by protocol family
    n_total   = len(devices)
    n_nvme    = sum(1 for d in devices if d["protocol"] == "nvme")
    n_ata     = sum(1 for d in devices if d["protocol"] in ("ata", "sat"))
    n_sas     = sum(1 for d in devices if d["protocol"] in ("scsi", "sas"))

    # ---- Common scalars ----
    add((2, 1, 1, 0), *_gauge(n_total))       # smartmonDeviceTableRowCount
    add((2, 1, 4, 0), *_gauge(n_nvme))        # smartmonDeviceCountNvme
    add((2, 1, 5, 0), *_gauge(n_ata))         # smartmonDeviceCountAta
    add((2, 1, 6, 0), *_gauge(n_sas))         # smartmonDeviceCountSas
    add((2, 1, 7, 0), *_gauge(_st.poll_failure_threshold))  # smartmonPollFailureThreshold

    # ---- Protocol-subtree scalars ----
    add((3, 1, 13, 0), *_gauge(n_nvme))       # smartmonNvmeHealthTableRowCount
    add((4, 1, 4, 0),  *_gauge(n_ata))        # smartmonSataHealthTableRowCount
    add((4, 1, 7, 0),  *_gauge(0))            # smartmonSataAttrTableRowCount (filled per-device below)
    add((5, 1, 4, 0),  *_gauge(n_sas))        # smartmonSasHealthTableRowCount
    add((5, 1, 7, 0),  *_gauge(n_sas * 2))    # smartmonSasErrorCounterTableRowCount (read+write per dev)
    add((6, 1, 1, 0),  *_gauge(0))            # smartmonSensorTableRowCount (filled below)

    used_d_idx: set = set()
    n_sata_attrs  = 0
    n_sensors     = 0

    for dev in sorted(devices, key=lambda d: (d["serial_number"], d["model_name"])):
        d_idx = _device_index(dev, used_d_idx)
        used_d_idx.add(d_idx)

        _add_common_device(add, dev, d_idx)

        proto = dev["protocol"]
        if proto == "nvme":
            _add_nvme_health(add, dev, d_idx)
        elif proto in ("ata", "sat"):
            _add_sata_health(add, dev, d_idx)
            n_sata_attrs += _add_sata_attrs(add, dev, d_idx)
        elif proto in ("scsi", "sas"):
            _add_sas_health(add, dev, d_idx)
            _add_sas_error_counters(add, dev, d_idx)

        n_sensors += _add_sensors(add, dev, d_idx)

    # Patch correct counts now that per-device builders have run
    entries[:] = [e for e in entries if e[0] != _full((4, 1, 7, 0))
                                     and e[0] != _full((6, 1, 1, 0))]
    add((4, 1, 7, 0), *_gauge(n_sata_attrs))
    add((6, 1, 1, 0), *_gauge(n_sensors))

    # ---- Fingerprint tables; advance LastChange only when content changes ----
    _LC_MAP = {
        "device":      (2, 1, 2, 0),
        "nvme_health": (3, 1, 14, 0),
        "sata_health": (4, 1, 5, 0),
        "sata_attr":   (4, 1, 8, 0),
        "sas_health":  (5, 1, 5, 0),
        "sas_err":     (5, 1, 8, 0),
        "sensor":      (6, 1, 2, 0),
    }
    for tname, lc_suffix in _LC_MAP.items():
        fp = _table_fingerprint(entries, _TABLE_PREFIXES[tname])
        if fp != _st.checksums.get(tname):
            _st.checksums[tname]  = fp
            _st.timestamps[tname] = ts_iso
            LOGGER.notice("table %s changed (fp %08x)", tname, fp & 0xFFFFFFFF)
        add(lc_suffix, "string", _st.timestamps.get(tname, ts_iso))

    entries.sort(key=lambda e: e[0])
    _st.oid_keys = [e[0] for e in entries]
    _st.oid_map  = {e[0]: (e[1], e[2]) for e in entries}
    LOGGER.debug("OID table built: %d entries", len(entries))


# --------------------------------------------------------------------------
# Common device table  (.2.1.3.1)
# --------------------------------------------------------------------------

def _add_common_device(add, dev: dict, d_idx: int) -> None:
    T = (2, 1, 3, 1)
    poll_time = dev.get("poll_time")
    smart_ok  = dev.get("smart_passed")
    poll_result = 1 if dev.get("read_error") is None else 6   # ok / parseError

    add(T+(2,  d_idx), *_string(dev["name"]))
    add(T+(3,  d_idx), *_string(dev["device_path"]))
    add(T+(4,  d_idx), *_integer(dev["device_type"]))
    add(T+(5,  d_idx), *(_datetimeval(poll_time) if poll_time else _string("")))
    add(T+(6,  d_idx), *_integer(poll_result))
    add(T+(7,  d_idx), *_gauge(0))                             # lastPollExitStatus
    add(T+(8,  d_idx), *_integer(0))                           # physicalIndex
    add(T+(9,  d_idx), *_string(dev.get("device_path", "")))   # uris
    add(T+(10, d_idx), *_string(dev["model_family"]))
    add(T+(11, d_idx), *_string(dev["model_name"]))
    add(T+(12, d_idx), *_string(dev["serial_number"]))
    add(T+(13, d_idx), *_string(dev["firmware_version"]))
    add(T+(14, d_idx), *_string(dev["wwn"]))


# --------------------------------------------------------------------------
# NVMe health table  (.3.1.15.1)
# --------------------------------------------------------------------------

def _parse_nvme_health(raw: dict) -> dict:
    h = raw.get("nvme_smart_health_information_log") or {}
    return {
        "critical_warning":        h.get("critical_warning", 0),
        "available_spare":         h.get("available_spare", 0),
        "available_spare_threshold": h.get("available_spare_threshold", 0),
        "percentage_used":         h.get("percentage_used", 0),
        "data_units_read":         h.get("data_units_read", 0),
        "data_units_written":      h.get("data_units_written", 0),
        "host_reads":              h.get("host_reads", 0),
        "host_writes":             h.get("host_writes", 0),
        "controller_busy_minutes": h.get("controller_busy_time", 0),
        "power_cycles":            h.get("power_cycles", 0),
        "power_on_hours":          h.get("power_on_hours", 0),
        "unsafe_shutdowns":        h.get("unsafe_shutdowns", 0),
        "media_errors":            h.get("media_errors", 0),
        "num_err_log_entries":     h.get("num_err_log_entries", 0),
        "warning_temp_time":       h.get("warning_temp_time", 0),
        "critical_comp_time":      h.get("critical_comp_time_minutes", 0),
    }


def _add_nvme_health(add, dev: dict, d_idx: int) -> None:
    """NVMe health table (.3.1.15.1) — INDEX { smartmonDeviceIndex, healthIdx(=1) }.
    Cols 3-6 are commented out in MIB (moved to SENSOR-MIB)."""
    T  = (3, 1, 15, 1)
    h  = _parse_nvme_health(dev["raw"])
    hi = 1   # single health row per controller
    smart_ok = dev.get("smart_passed")
    overall  = 1 if smart_ok else (2 if smart_ok is False else 0)

    add(T+(1,  d_idx, hi), *_integer(overall))
    add(T+(2,  d_idx, hi), *_gauge(h["critical_warning"]))
    # cols 3-6 omitted (reserved/commented-out in MIB)
    add(T+(7,  d_idx, hi), *_counter64(h["data_units_read"]))
    add(T+(8,  d_idx, hi), *_counter64(h["data_units_written"]))
    add(T+(9,  d_idx, hi), *_counter64(h["data_units_read"]  * 512000))
    add(T+(10, d_idx, hi), *_counter64(h["data_units_written"] * 512000))
    add(T+(11, d_idx, hi), *_counter64(h["host_reads"]))
    add(T+(12, d_idx, hi), *_counter64(h["host_writes"]))
    add(T+(13, d_idx, hi), *_counter64(h["controller_busy_minutes"]))
    add(T+(14, d_idx, hi), *_counter64(h["power_cycles"]))
    add(T+(15, d_idx, hi), *_counter64(h["power_on_hours"]))
    add(T+(16, d_idx, hi), *_counter64(h["unsafe_shutdowns"]))
    add(T+(17, d_idx, hi), *_counter64(h["media_errors"]))
    add(T+(18, d_idx, hi), *_counter64(h["num_err_log_entries"]))
    add(T+(19, d_idx, hi), *_counter64(h["warning_temp_time"]))
    add(T+(20, d_idx, hi), *_counter64(h["critical_comp_time"]))
    add(T+(22, d_idx, hi), *_gauge(0))        # currentSelfTestOperationValue
    add(T+(23, d_idx, hi), *_string(""))


# --------------------------------------------------------------------------
# SATA health table  (.4.1.6.1)
# --------------------------------------------------------------------------

def _parse_sata_health(raw: dict) -> dict:
    ata  = raw.get("ata_smart_data") or {}
    offl = ata.get("offline_data_collection") or {}
    st   = ata.get("self_test") or {}
    offl_val = int((offl.get("status") or {}).get("value", 0))
    st_val   = int((st.get("status") or {}).get("value", 0))
    err_log  = (raw.get("ata_smart_error_log") or {}).get("extended") or {}
    sct      = raw.get("ata_sct_status") or {}
    sct_temp = sct.get("temperature") or {}
    pot = raw.get("power_on_time") or {}
    return {
        "power_on_hours":          int(pot.get("hours", 0)),
        "power_cycles":            int(raw.get("power_cycle_count", 0) or 0),
        "offline_status":          _ATA_OFFLINE_STATUS.get(offl_val & 0x7F, 0),
        "selftest_exec_status":    _SELFTEST_EXEC_STATUS.get((st_val >> 4) & 0xF, 0),
        "selftest_exec_remaining": (st_val & 0xF) * 10,
        "error_log_count":         int(err_log.get("count", 0) or 0),
        # SCT status fields
        "sct_format_version":      int(sct.get("format_version", 0) or 0),
        "sct_version":             int(sct.get("sct_version", 0) or 0),
        "sct_device_state":        int((sct.get("device_state") or {}).get("value", 0)),
        "sct_temp_power_cycle_min": int(sct_temp.get("power_cycle_min", 0) or 0),
        "sct_temp_power_cycle_max": int(sct_temp.get("power_cycle_max", 0) or 0),
        "sct_temp_lifetime_min":    int(sct_temp.get("lifetime_min", 0) or 0),
        "sct_temp_lifetime_max":    int(sct_temp.get("lifetime_max", 0) or 0),
        "sct_temp_under_limit":     int(sct_temp.get("under_limit_count", 0) or 0),
        "sct_temp_over_limit":      int(sct_temp.get("over_limit_count", 0) or 0),
        "sct_smart_passed":         1 if raw.get("smart_status", {}).get("passed") else 2,
    }


def _add_sata_health(add, dev: dict, d_idx: int) -> None:
    """SATA health table (.4.1.6.1) — INDEX { smartmonDeviceIndex }."""
    T = (4, 1, 6, 1)
    h = _parse_sata_health(dev["raw"])
    smart_ok = dev.get("smart_passed")
    overall  = 1 if smart_ok else (2 if smart_ok is False else 0)

    # col 1-9 core health
    add(T+(1,  d_idx), *_integer(overall))
    add(T+(2,  d_idx), *_integer(h["offline_status"]))
    add(T+(3,  d_idx), *_integer(h["selftest_exec_status"]))
    add(T+(4,  d_idx), *_counter64(h["power_cycles"]))
    add(T+(5,  d_idx), *_counter64(h["power_on_hours"]))
    add(T+(6,  d_idx), *_gauge(h["error_log_count"]))
    # col 11-17 SCT status
    add(T+(11, d_idx), *_gauge(h["sct_format_version"]))
    add(T+(12, d_idx), *_gauge(h["sct_version"]))
    add(T+(13, d_idx), *_gauge(h["sct_device_state"]))
    add(T+(14, d_idx), *_integer(h["sct_temp_power_cycle_min"]))
    add(T+(15, d_idx), *_integer(h["sct_temp_power_cycle_max"]))
    add(T+(16, d_idx), *_integer(h["sct_temp_lifetime_min"]))
    add(T+(17, d_idx), *_integer(h["sct_temp_lifetime_max"]))
    add(T+(18, d_idx), *_gauge(h["sct_temp_under_limit"]))
    add(T+(19, d_idx), *_gauge(h["sct_temp_over_limit"]))
    add(T+(20, d_idx), *_integer(h["sct_smart_passed"]))
    add(T+(21, d_idx), *_gauge(h["selftest_exec_remaining"]))


# --------------------------------------------------------------------------
# SATA attribute table  (.4.1.9.1)
# --------------------------------------------------------------------------

def _parse_sata_attrs(raw: dict) -> List[dict]:
    attrs_raw = (raw.get("ata_smart_attributes") or {}).get("table") or []
    result = []
    for a in attrs_raw:
        flags   = a.get("flags") or {}
        raw_a   = a.get("raw") or {}
        thresh  = int(a.get("thresh", 0) or 0)
        when_f  = str(a.get("when_failed", "") or "")
        if thresh == 0:
            status = -1   # notRelevant
        elif when_f == "now":
            status = _ATTR_STATUS_FAILING
        elif when_f and when_f != "-":
            status = _ATTR_STATUS_FAILED
        else:
            status = _ATTR_STATUS_OK
        result.append({
            "id":          int(a.get("id", 0)),
            "name":        str(a.get("name", "")),
            "flags_value": int(flags.get("value", 0) or 0),
            "attr_type":   1 if flags.get("prefailure") else 2,
            "attr_updated": 1 if flags.get("updated_online") else 2,
            "value":       int(a.get("value", 0) or 0),
            "worst":       int(a.get("worst", 0) or 0),
            "thresh":      thresh,
            "raw_value":   int(raw_a.get("value", 0) or 0),
            "raw_string":  str(raw_a.get("string", "") or ""),
            "status":      status,
        })
    return result


def _add_sata_attrs(add, dev: dict, d_idx: int) -> int:
    T    = (4, 1, 9, 1)
    rows = _parse_sata_attrs(dev["raw"])
    for a in rows:
        ai = a["id"]
        add(T+(2,  d_idx, ai), *_string(a["name"]))
        add(T+(3,  d_idx, ai), *_gauge(a["flags_value"]))
        add(T+(4,  d_idx, ai), *_integer(a["attr_type"]))
        add(T+(5,  d_idx, ai), *_integer(a["attr_updated"]))
        add(T+(6,  d_idx, ai), *_gauge(a["value"]))
        add(T+(7,  d_idx, ai), *_gauge(a["worst"]))
        add(T+(8,  d_idx, ai), *_gauge(a["thresh"]))
        add(T+(9,  d_idx, ai), *_counter64(a["raw_value"]))
        add(T+(10, d_idx, ai), *_string(a["raw_string"]))
        add(T+(11, d_idx, ai), *_integer(a["status"]))
    return len(rows)


# --------------------------------------------------------------------------
# SAS health table  (.5.1.6.1)
# --------------------------------------------------------------------------

def _parse_sas_health(raw: dict) -> dict:
    smart_ok = (raw.get("smart_status") or {}).get("passed")
    return {
        "overall":          1 if smart_ok else (2 if smart_ok is False else 0),
        "grown_defects":    int(raw.get("scsi_grown_defect_list", 0) or 0),
        "non_medium_errors": 0,
        "pending_defects":  0,
    }


def _add_sas_health(add, dev: dict, d_idx: int) -> None:
    """SAS health table (.5.1.6.1) — INDEX { smartmonDeviceIndex, healthIdx(=1) }."""
    T  = (5, 1, 6, 1)
    h  = _parse_sas_health(dev["raw"])
    hi = 1
    add(T+(1, d_idx, hi), *_integer(h["overall"]))
    add(T+(2, d_idx, hi), *_gauge(h["grown_defects"]))
    add(T+(3, d_idx, hi), *_counter64(h["non_medium_errors"]))
    add(T+(4, d_idx, hi), *_truthvalue(False))  # informationalExceptions
    add(T+(5, d_idx, hi), *_gauge(h["pending_defects"]))


# --------------------------------------------------------------------------
# SAS error counter table  (.5.1.9.1)
# --------------------------------------------------------------------------

def _parse_sas_error_counters(raw: dict) -> List[dict]:
    ecl = raw.get("scsi_error_counter_log") or {}
    rows = []
    for dir_name, dir_id in (("read", 1), ("write", 2)):
        e = ecl.get(dir_name) or {}
        if not e:
            continue
        gb = float(e.get("gigabytes_processed", 0) or 0)
        rows.append({
            "direction":          dir_id,
            "ecc_fast":           int(e.get("errors_corrected_by_eccfast", 0) or 0),
            "ecc_delayed":        int(e.get("errors_corrected_by_eccdelayed", 0) or 0),
            "rereads_rewrites":   int(e.get("errors_corrected_by_rereads_rewrites", 0) or 0),
            "total_corrected":    int(e.get("total_errors_corrected", 0) or 0),
            "algorithm_invocations": int(e.get("correction_algorithm_invocations", 0) or 0),
            "bytes_processed":    int(gb * 1_000_000_000),
            "uncorrected_errors": int(e.get("total_uncorrected_errors", 0) or 0),
        })
    return rows


def _add_sas_error_counters(add, dev: dict, d_idx: int) -> None:
    """SAS error counter table (.5.1.9.1) — INDEX { smartmonDeviceIndex, direction }.
    Col 1 is direction (NOT-ACCESSIBLE index); data starts at col 2."""
    T    = (5, 1, 9, 1)
    rows = _parse_sas_error_counters(dev["raw"])
    for r in rows:
        di = r["direction"]
        add(T+(2, d_idx, di), *_counter64(r["ecc_delayed"]))
        add(T+(3, d_idx, di), *_counter64(r["ecc_fast"]))
        add(T+(4, d_idx, di), *_counter64(r["rereads_rewrites"]))
        add(T+(5, d_idx, di), *_counter64(r["total_corrected"]))
        add(T+(6, d_idx, di), *_counter64(r["algorithm_invocations"]))
        add(T+(7, d_idx, di), *_counter64(r["bytes_processed"]))
        add(T+(8, d_idx, di), *_counter64(r["uncorrected_errors"]))


# --------------------------------------------------------------------------
# Sensor table  (.6.1.3.1)
# --------------------------------------------------------------------------

def _extract_sensors(dev: dict) -> List[dict]:
    raw   = dev["raw"]
    proto = dev["protocol"]
    poll_time = dev.get("poll_time") or datetime.now(timezone.utc)
    sensors: List[dict] = []

    def sensor(idx, stype, name, source, scale, precision, value, status,
               units_display, hi_crit=None, hi_warn=None):
        sensors.append({
            "idx": idx, "type": stype, "name": name, "source": source,
            "scale": scale, "precision": precision, "value": value,
            "status": status, "units_display": units_display,
            "hi_crit": hi_crit, "hi_warn": hi_warn,
            "timestamp": poll_time,
        })

    temp = raw.get("temperature") or {}
    t_current = temp.get("current")
    if t_current is not None:
        t_crit = temp.get("op_limit") or temp.get("limit_max") or 70
        sensor(1, 3, "temperature", "temperature.current",
               9, 0, int(t_current), 1, "C",
               hi_crit=int(t_crit), hi_warn=int(t_crit) - 5)

    if proto == "nvme":
        h = raw.get("nvme_smart_health_information_log") or {}
        spare = h.get("available_spare")
        if spare is not None:
            sensor(2, 10, "available_spare", "nvme_smart_health_information_log.available_spare",
                   9, 0, int(spare), 1, "%")
        pct_used = h.get("percentage_used")
        if pct_used is not None:
            sensor(3, 10, "percentage_used", "nvme_smart_health_information_log.percentage_used",
                   9, 0, int(pct_used), 1, "%")
        # Per-sensor temperatures (sensor1 onwards in the NVMe log)
        for i, t_val in enumerate(h.get("temperature_sensors") or [], start=1):
            if t_val is not None:
                sensor(10 + i, 3, f"temperature_sensor{i}",
                       f"nvme_smart_health_information_log.temperature_sensors[{i}]",
                       9, 0, int(t_val), 1, "C")

    return sensors


def _add_sensors(add, dev: dict, d_idx: int) -> int:
    T       = (6, 1, 3, 1)
    sensors = _extract_sensors(dev)
    for s in sensors:
        si = s["idx"]
        add(T+(2,  d_idx, si), *_integer(s["type"]))
        add(T+(3,  d_idx, si), *_string(s["name"]))
        add(T+(4,  d_idx, si), *_string(s["source"]))
        add(T+(5,  d_idx, si), *_integer(s["scale"]))
        add(T+(6,  d_idx, si), *_gauge(s["precision"]))
        add(T+(7,  d_idx, si), *_integer(s["value"]))
        add(T+(8,  d_idx, si), *_integer(s["status"]))
        add(T+(9,  d_idx, si), *_string(s["units_display"]))
        add(T+(10, d_idx, si), *_datetimeval(s["timestamp"]))
        add(T+(11, d_idx, si), *_gauge(0))                  # updateRate
        add(T+(12, d_idx, si), *_integer(s["hi_crit"] or 0))
        add(T+(13, d_idx, si), *_integer(s["hi_warn"] or 0))
        add(T+(14, d_idx, si), *_integer(0))                 # loWarn
        add(T+(15, d_idx, si), *_integer(0))                 # loCrit
    return len(sensors)


# ==========================================================================
# Part 4 — AgentX protocol wiring
# ==========================================================================

DEFAULT_AGENTX_SOCKET = os.environ.get("AGENTX_SOCKET", "/var/agentx/master")
BASE_OID_STR = "1.3.6.1.4.1.65891.1.1"
BASE_OID_TUPLE = tuple(int(p) for p in BASE_OID_STR.split("."))
if BASE_OID != BASE_OID_TUPLE:
    raise RuntimeError(f"BASE_OID {BASE_OID!r} != {BASE_OID_STR}")

Oid = Tuple[int, ...]


def _agentx_oid_str(oid: Oid) -> str:
    return ".".join(str(p) for p in oid)


def _scalar_oid(suffix: Iterable[int]) -> str:
    full = _full(tuple(suffix))
    if full[-1] != 0:
        raise ValueError(f"scalar suffix must end with .0: {suffix}")
    return _agentx_oid_str(full[:-1])


def _table_oid(table_suffix: Iterable[int]) -> str:
    return _agentx_oid_str(_full(tuple(table_suffix)))


def _as_int(value: object) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _as_text(value: object, limit: int = 1023) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= limit else text[:limit]


def _make_value(agent: Any, snmp_type: str, value: object) -> Any:
    if snmp_type == "counter64":
        return agent.Counter64(max(0, _as_int(value)))
    if snmp_type == "gauge":
        return agent.Unsigned32(max(0, min(_as_int(value), 0xFFFFFFFF)))
    if snmp_type == "integer":
        return agent.Integer32(_as_int(value))
    if snmp_type == "string":
        return agent.OctetString(_as_text(value))
    if snmp_type == "datetimeval":
        raw = _encode_datetimeval(value) if isinstance(value, datetime) else b""
        return agent.OctetString(raw)
    raise ValueError(f"unsupported SNMP type {snmp_type!r}")


def _make_scalar(agent: Any, oidstr: str, snmp_type: str) -> Any:
    if snmp_type == "counter64":
        return agent.Counter64(oidstr=oidstr, writable=False)
    if snmp_type == "gauge":
        return agent.Unsigned32(oidstr=oidstr, writable=False)
    if snmp_type == "integer":
        return agent.Integer32(oidstr=oidstr, writable=False)
    if snmp_type in ("string", "datetimeval"):
        return agent.OctetString(oidstr=oidstr, writable=False)
    raise ValueError(f"unsupported scalar type {snmp_type!r}")


def _scalar_definitions() -> Dict[Oid, str]:
    return {
        # Common scalars
        _full((2, 1, 1, 0)): "gauge",    # deviceTableRowCount
        _full((2, 1, 2, 0)): "string",   # deviceTableLastChange
        _full((2, 1, 4, 0)): "gauge",    # deviceCountNvme
        _full((2, 1, 5, 0)): "gauge",    # deviceCountAta
        _full((2, 1, 6, 0)): "gauge",    # deviceCountSas
        _full((2, 1, 7, 0)): "gauge",    # pollFailureThreshold
        # NVMe scalars
        _full((3, 1, 13, 0)): "gauge",   # nvmeHealthTableRowCount
        _full((3, 1, 14, 0)): "string",  # nvmeHealthTableLastChange
        # SATA scalars
        _full((4, 1, 4, 0)): "gauge",    # sataHealthTableRowCount
        _full((4, 1, 5, 0)): "string",   # sataHealthTableLastChange
        _full((4, 1, 7, 0)): "gauge",    # sataAttrTableRowCount
        _full((4, 1, 8, 0)): "string",   # sataAttrTableLastChange
        # SAS scalars
        _full((5, 1, 4, 0)): "gauge",    # sasHealthTableRowCount
        _full((5, 1, 5, 0)): "string",   # sasHealthTableLastChange
        _full((5, 1, 7, 0)): "gauge",    # sasErrorCounterTableRowCount
        _full((5, 1, 8, 0)): "string",   # sasErrorCounterTableLastChange
        # Sensor scalars
        _full((6, 1, 1, 0)): "gauge",    # sensorTableRowCount
        _full((6, 1, 2, 0)): "string",   # sensorTableLastChange
    }


TABLE_DEFINITIONS: Dict[str, dict] = {
    "device": {
        "oid_suffix": (2, 1, 3),
        "entry_prefix": _full((2, 1, 3, 1)),
        "indexes": 1,
        "columns": {
            2: "string", 3: "string", 4: "integer", 5: "datetimeval",
            6: "integer", 7: "gauge",  8: "integer", 9: "string",
            10: "string", 11: "string", 12: "string", 13: "string", 14: "string",
        },
    },
    "nvme_health": {
        "oid_suffix": (3, 1, 15),
        "entry_prefix": _full((3, 1, 15, 1)),
        "indexes": 2,
        "columns": {
            1: "integer", 2: "gauge",
            7: "counter64", 8: "counter64", 9: "counter64", 10: "counter64",
            11: "counter64", 12: "counter64", 13: "counter64", 14: "counter64",
            15: "counter64", 16: "counter64", 17: "counter64", 18: "counter64",
            19: "counter64", 20: "counter64",
            22: "gauge", 23: "string",
        },
    },
    "sata_health": {
        "oid_suffix": (4, 1, 6),
        "entry_prefix": _full((4, 1, 6, 1)),
        "indexes": 1,
        "columns": {
            1: "integer", 2: "integer", 3: "integer",
            4: "counter64", 5: "counter64", 6: "gauge",
            11: "gauge", 12: "gauge", 13: "gauge",
            14: "integer", 15: "integer", 16: "integer", 17: "integer",
            18: "gauge", 19: "gauge", 20: "integer", 21: "gauge",
        },
    },
    "sata_attr": {
        "oid_suffix": (4, 1, 9),
        "entry_prefix": _full((4, 1, 9, 1)),
        "indexes": 2,
        "columns": {
            2: "string", 3: "gauge", 4: "integer", 5: "integer",
            6: "gauge", 7: "gauge", 8: "gauge", 9: "counter64",
            10: "string", 11: "integer",
        },
    },
    "sas_health": {
        "oid_suffix": (5, 1, 6),
        "entry_prefix": _full((5, 1, 6, 1)),
        "indexes": 2,
        "columns": {
            1: "integer", 2: "gauge", 3: "counter64", 4: "integer", 5: "gauge",
        },
    },
    "sas_err": {
        "oid_suffix": (5, 1, 9),
        "entry_prefix": _full((5, 1, 9, 1)),
        "indexes": 2,
        "columns": {
            2: "counter64", 3: "counter64", 4: "counter64", 5: "counter64",
            6: "counter64", 7: "counter64", 8: "counter64",
        },
    },
    "sensor": {
        "oid_suffix": (6, 1, 3),
        "entry_prefix": _full((6, 1, 3, 1)),
        "indexes": 2,
        "columns": {
            2: "integer", 3: "string", 4: "string", 5: "integer",
            6: "gauge", 7: "integer", 8: "integer", 9: "string",
            10: "datetimeval", 11: "gauge",
            12: "integer", 13: "integer", 14: "integer", 15: "integer",
        },
    },
}


def _register_scalars(agent: Any) -> Dict[Oid, Any]:
    scalars = {}
    for oid, snmp_type in _scalar_definitions().items():
        scalars[oid] = _make_scalar(agent, _scalar_oid(oid[len(BASE_OID):]), snmp_type)
    return scalars


def _register_tables(agent: Any) -> Dict[str, Any]:
    tables = {}
    for name, defn in TABLE_DEFINITIONS.items():
        columns = [
            (col, _make_value(agent, snmp_type, "" if snmp_type in ("string", "datetimeval") else 0))
            for col, snmp_type in defn["columns"].items()
        ]
        tables[name] = agent.Table(
            oidstr=_table_oid(defn["oid_suffix"]),
            indexes=[agent.Unsigned32() for _ in range(defn["indexes"])],
            columns=columns,
        )
    return tables


def _split_table_oid(oid: Oid, prefix: Oid, index_count: int):
    if oid[:len(prefix)] != prefix:
        return None
    rest = oid[len(prefix):]
    if len(rest) != index_count + 1:
        return None
    return rest[0], rest[1:]


def _publish_scalars(scalars: Dict[Oid, Any]) -> None:
    now = datetime.now(timezone.utc)
    defns = _scalar_definitions()
    for oid, scalar in scalars.items():
        snmp_type, value = _st.oid_map.get(oid, (None, None))
        if snmp_type is None:
            if defns[oid] == "string":
                scalar.update(now.isoformat().encode())
            else:
                scalar.update(0)
            continue
        if snmp_type == "datetimeval":
            scalar.update(_encode_datetimeval(value) if isinstance(value, datetime) else b"")
        elif snmp_type == "string":
            scalar.update(_as_text(value).encode())
        else:
            scalar.update(_as_int(value))


def _publish_tables(agent: Any, tables: Dict[str, Any]) -> None:
    for name, table in tables.items():
        defn        = TABLE_DEFINITIONS[name]
        prefix      = defn["entry_prefix"]
        index_count = defn["indexes"]
        columns     = defn["columns"]
        rows: Dict[Tuple, Dict[int, Tuple[str, object]]] = {}

        for oid, (snmp_type, value) in _st.oid_map.items():
            split = _split_table_oid(oid, prefix, index_count)
            if split is None:
                continue
            column, indexes = split
            if column not in columns:
                continue
            rows.setdefault(indexes, {})[column] = (snmp_type, value)

        table.clear()
        for indexes in sorted(rows):
            row = table.addRow([agent.Unsigned32(idx) for idx in indexes])
            for col, snmp_type in columns.items():
                vtype, val = rows[indexes].get(col, (snmp_type, "" if snmp_type in ("string", "datetimeval") else 0))
                row.setRowCell(col, _make_value(agent, vtype, val))


def _refresh_and_publish(agent: Any, scalars: Dict[Oid, Any], tables: Dict[str, Any]) -> None:
    before = time.monotonic()
    _refresh()
    _publish_scalars(scalars)
    _publish_tables(agent, tables)
    LOG.info("published %d OIDs in %.2fs", len(_st.oid_map), time.monotonic() - before)


def _set_error_scalar(code: int, message: str) -> None:
    pass  # no top-level error scalars in this MIB


def _handle_collection_error(exc: CollectionError, ts: datetime) -> None:
    LOGGER.error("collection error %d: %s", exc.code, exc.message)
    if exc.code in _CLEANUP_CODES or not _st.oid_keys:
        _build([], ts, exc.code, str(exc))


def _collect_and_build(ts: datetime) -> None:
    files   = _discover_devices(_st.state_dir, _st.config_devices)
    devices = []
    errors  = 0
    for path in files:
        dev = _parse_device_json(path)
        if dev["read_error"]:
            LOGGER.warning("parse error %s: %s", path, dev["read_error"])
            errors += 1
        else:
            devices.append(dev)
    err_code = EXIT_PARTIAL_FAILURE if errors else EXIT_SUCCESS
    err_msg  = f"{errors} device(s) failed to parse" if errors else ""
    _build(devices, ts, err_code, err_msg)
    LOGGER.notice("built OID table: %d devices (%d errors)", len(devices), errors)


def _refresh() -> None:
    now = time.monotonic()
    if _st.oid_keys and now - _st.last_load < _st.ttl:
        LOGGER.debug("cache hit (age=%.1fs ttl=%ds)", now - _st.last_load, _st.ttl)
        return
    LOGGER.notice("refreshing data (age=%.1fs ttl=%ds)",
                  now - _st.last_load if _st.last_load else 0, _st.ttl)
    ts = datetime.now(timezone.utc)
    try:
        _collect_and_build(ts)
    except CollectionError as exc:
        _handle_collection_error(exc, ts)
    except Exception as exc:
        LOGGER.error("unexpected collection failure: %s", exc, exc_info=True)
        if _st.oid_keys:
            pass   # keep last good data
        else:
            _build([], ts, EXIT_PARTIAL_FAILURE, f"unexpected: {exc}")
    _st.last_load = now


def _load_config(path: str) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    # Try YAML first (only if result is a dict)
    try:
        import yaml
        with open(path) as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data
    except ImportError:
        pass
    except Exception:
        pass
    # Minimal key=value parser — supports 'key: val' and 'key val' (C++ conf format)
    cfg: dict = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("---"):
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    cfg[k.strip()] = v.strip()
                else:
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        cfg[parts[0]] = parts[1]
    except OSError as exc:
        LOGGER.warning("could not read config %s: %s", path, exc)
    return cfg


def _register_wakeup_alarm(interval_s: int) -> Any:
    import ctypes
    import netsnmpapi
    SA_REPEAT = 1
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_void_p)
    callback = callback_type(lambda reg, arg: None)
    lib = netsnmpapi.libnsa
    lib.snmp_alarm_register.restype  = ctypes.c_uint
    lib.snmp_alarm_register.argtypes = [
        ctypes.c_uint, ctypes.c_uint, callback_type, ctypes.c_void_p,
    ]
    lib.snmp_alarm_register(max(1, int(interval_s)), SA_REPEAT, callback, None)
    return callback


def _configure_smartmon(args: "argparse.Namespace", cfg: dict) -> None:
    ttl       = args.ttl if args.ttl is not None else int(cfg.get("ttl", CACHE_TTL))
    log_level = args.log_level or str(cfg.get("log_level", "WARNING")).upper()
    log_path  = args.log_file  or cfg.get("log_file")
    devices   = cfg.get("devices")

    _st.ttl           = ttl
    _st.state_dir     = args.state_dir or cfg.get("state_dir", "")
    _st.config_devices = list(devices) if devices else None

    level = {"VERBOSE": VERBOSE, "NOTICE": NOTICE}.get(
        log_level, getattr(logging, log_level, logging.WARNING)
    )
    handlers: List[Any] = [logging.StreamHandler(sys.stderr)]
    if log_path:
        handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="SMARTMON-*-MIB AgentX subagent")
    parser.add_argument("--config", "-c", metavar="PATH",
                        default="/etc/snmp/extension/smartmon.yaml",
                        help="path to YAML (or key=value) config file (default: %(default)s)")
    parser.add_argument("--state-dir",    metavar="PATH", default=None,
                        help="directory containing smartd --jsonstate *.json files")
    parser.add_argument("--ttl",          type=int, default=None, metavar="SEC",
                        help=f"cache TTL in seconds before re-reading state files (default: {CACHE_TTL})")
    parser.add_argument("--log-level",    default=None,
                        choices=["DEBUG", "VERBOSE", "INFO", "NOTICE", "WARNING", "ERROR"],
                        help="minimum log severity written to stderr / log-file (default: WARNING)")
    parser.add_argument("--log-file",     metavar="PATH", default=None,
                        help="append log output to this file in addition to stderr")
    parser.add_argument("--agentx-socket", default=DEFAULT_AGENTX_SOCKET,
                        help="path to the net-snmp AgentX master socket (default: %(default)s)")
    parser.add_argument("-f", dest="foreground", action="store_true",
                        help="run in foreground (default)")
    parser.add_argument("--once", action="store_true",
                        help="collect and publish once, then exit")
    args = parser.parse_args()

    cfg = _load_config(args.config)

    # Let config file supply agentx_socket if not on command line
    agentx_socket = args.agentx_socket
    if agentx_socket == DEFAULT_AGENTX_SOCKET and "agentx_socket" in cfg:
        agentx_socket = cfg["agentx_socket"]

    _configure_smartmon(args, cfg)

    if not _st.state_dir:
        LOGGER.error("state_dir not configured; pass --state-dir or set it in the config file")
        sys.exit(EXIT_CONFIG_ERROR)

    try:
        import netsnmpagent
    except ImportError:
        LOGGER.error("netsnmpagent module not found; install python3-netsnmpagent")
        sys.exit(EXIT_DEPENDENCY_MISSING)

    agent_cls = getattr(netsnmpagent, "Agent", None) or getattr(netsnmpagent, "netsnmpAgent", None)
    if agent_cls is None:
        LOGGER.error("unsupported netsnmpagent package (no Agent/netsnmpAgent class)")
        sys.exit(EXIT_DEPENDENCY_MISSING)

    agent = agent_cls(
        AgentName="smartmonAgent",
        MasterSocket=agentx_socket,
        UseMIBFiles=False,
    )
    scalars = _register_scalars(agent)
    tables  = _register_tables(agent)

    agent.start()
    _refresh_and_publish(agent, scalars, tables)

    if args.once:
        return

    wakeup_alarm = _register_wakeup_alarm(1)   # keep referenced
    next_refresh = time.monotonic() + max(1, _st.ttl)

    try:
        while True:
            agent.check_and_process(block=True)
            now = time.monotonic()
            if now >= next_refresh:
                _refresh_and_publish(agent, scalars, tables)
                next_refresh = now + max(1, _st.ttl)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
