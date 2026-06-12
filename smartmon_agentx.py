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

def _msb_pos(v: int) -> int:
    """Return the 0-based position of the most significant set bit (0 if v==0)."""
    return v.bit_length() - 1 if v > 0 else 0


def _sata_ver_enum(sv: int) -> int:
    """Encode sata_version.value bitmask to SmartmonSataVersion enum (msb+1, capped at 12)."""
    sv = sv & 0x0FFF
    msb = (sv & 0x0FFF).bit_length() - 1 if sv else -1
    return 12 if msb >= 11 else (msb + 1 if msb >= 0 else 0)


def _if_speed_mbps(ispd: dict) -> int:
    ups = int(ispd.get("units_per_second", 0) or 0)
    bpu = int(ispd.get("bits_per_unit", 0) or 0)
    if ups and bpu:
        return ups * bpu // 1_000_000
    return 0


def _bits(val: int, nbits: int = 8) -> tuple:
    """Encode an integer as an SNMP BITS OCTET STRING (MSB of first byte = bit 0)."""
    nbytes = (nbits + 7) // 8
    data = bytearray(nbytes)
    for i in range(nbits):
        if int(val) & (1 << i):
            data[i // 8] |= 0x80 >> (i % 8)
    return ("bits", bytes(data))

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


_PCI_VENDORS: Optional[Dict[int, str]] = None
_PCI_IDS_PATH = "/usr/share/misc/pci.ids"

def _pci_vendor_name(vendor_id: int) -> str:
    """Return vendor name from pci.ids for the given numeric ID, or ''."""
    global _PCI_VENDORS
    if _PCI_VENDORS is None:
        _PCI_VENDORS = {}
        try:
            with open(_PCI_IDS_PATH, errors="replace") as fh:
                for line in fh:
                    if line.startswith("#") or line.startswith("\t") or not line.strip():
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        try:
                            _PCI_VENDORS[int(parts[0], 16)] = parts[1].strip()
                        except ValueError:
                            pass
        except OSError:
            pass
    return _PCI_VENDORS.get(vendor_id, "")


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
    timestamps:     dict   # table key -> datetime
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
        # Per-device selftest progress: dev_idx -> {start_ns, last_remaining, polling_min, estimated_completion}
        self.selftest_progress: dict = {}


_st = _State()

# Table prefix tuples for fingerprinting (full OID prefix of each table entry)
_TABLE_PREFIXES = {
    "device":               _full((2, 1, 3, 1)),
    "nvme_controller":      _full((3, 1, 3, 1)),
    "nvme_namespace":       _full((3, 1, 6, 1)),
    "nvme_power_state":     _full((3, 1, 9, 1)),
    "nvme_lba_format":      _full((3, 1, 12, 1)),
    "nvme_health":          _full((3, 1, 15, 1)),
    "nvme_selftest":        _full((3, 1, 18, 1)),
    "nvme_errlog":          _full((3, 1, 21, 1)),
    "nvme_capability":      _full((3, 1, 24, 1)),
    "sata_health":          _full((4, 1, 6, 1)),
    "sata_attr":            _full((4, 1, 9, 1)),
    "sata_errorlog":        _full((4, 1, 12, 1)),
    "sata_errorcmd":        _full((4, 1, 15, 1)),
    "sata_selftest":        _full((4, 1, 18, 1)),
    "sata_erc":             _full((4, 1, 21, 1)),
    "sata_phyevent":        _full((4, 1, 24, 1)),
    "sata_selective":       _full((4, 1, 27, 1)),
    "sata_logdir":          _full((4, 1, 34, 1)),
    "sata_devstat":         _full((4, 1, 40, 1)),
    "sata_pending_defects": _full((4, 1, 43, 1)),
    "sas_health":           _full((5, 1, 6, 1)),
    "sas_err":              _full((5, 1, 9, 1)),
    "sensor":               _full((6, 1, 3, 1)),
}


_SATA_CHANGE_TABLE_NAMES = {
    1:  "smartmonSataInfoTable",
    2:  "smartmonSataHealthTable",
    3:  "smartmonSataAttrTable",
    4:  "smartmonSataErrorLogTable",
    5:  "smartmonSataErrorCmdTable",
    6:  "smartmonSataSelfTestTable",
    7:  "smartmonSataErcTable",
    8:  "smartmonSataPhyEventTable",
    9:  "smartmonSataSelectiveTestTable",
    10: "smartmonSataLogDirTable",
    11: "smartmonSataDevStatTable",
    12: "smartmonSataPendingDefectsTable",
}

_SATA_CHANGE_TABLE_LC_KEYS = {
    1:  None,            # sata_info has no dedicated LC timestamp
    2:  "sata_health",
    3:  "sata_attr",
    4:  "sata_errorlog",
    5:  "sata_errorcmd",
    6:  "sata_selftest",
    7:  "sata_erc",
    8:  "sata_phyevent",
    9:  "sata_selective",
    10: "sata_logdir",
    11: "sata_devstat",
    12: "sata_pending_defects",
}


def _sata_change_ts(table_id: int, fallback: datetime) -> datetime:
    key = _SATA_CHANGE_TABLE_LC_KEYS.get(table_id)
    if key:
        return _st.timestamps.get(key, fallback)
    return fallback


def _add_sata_changes(add, sata_dev_counts: Dict[int, Dict[int, int]],
                      sata_dev_subidx: set, ts: datetime,
                      total_counts: Dict[int, int]) -> None:
    """Populate the smartSATAChanges subtree (.4.1.2)."""
    # MetadataTable  (.4.1.2.1.1)  — 12 rows, INDEX { tableId }
    MT = (4, 1, 2, 1, 1)
    for tid in range(1, 13):
        row_count = total_counts.get(tid, 0)
        lc        = _sata_change_ts(tid, ts)
        add(MT+(2, tid), *_string(_SATA_CHANGE_TABLE_NAMES[tid]))
        add(MT+(3, tid), *_gauge(row_count))
        add(MT+(4, tid), *_datetimeval(lc))

    # ByDeviceTable  (.4.1.2.2.1)  — N_devices × 12 rows, INDEX { deviceIndex, tableId }
    BDT = (4, 1, 2, 2, 1)
    for d_idx, dc in sata_dev_counts.items():
        for tid in range(1, 13):
            row_count = dc.get(tid, 0)
            lc        = _sata_change_ts(tid, ts)
            add(BDT+(2, d_idx, tid), *_gauge(row_count))
            add(BDT+(3, d_idx, tid), *_datetimeval(lc))

    # BySubindexTable  (.4.1.2.3.1)  — INDEX { deviceIndex, tableId, subindex1 }
    BST = (4, 1, 2, 3, 1)
    for d_idx, tid, sub1 in sorted(sata_dev_subidx):
        lc = _sata_change_ts(tid, ts)
        add(BST+(4, d_idx, tid, sub1), *_datetimeval(lc))


def _build(devices: list, ts: datetime,
           error_code: int = EXIT_SUCCESS, error_string: str = "") -> None:
    """Rebuild the OID map from a list of parsed device dicts."""
    entries: List[Tuple] = []

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

    # ---- Protocol-subtree scalars (placeholders filled after device loop) ----
    add((3, 1, 1, 0),  *_gauge(0))            # nvmeControllerTableRowCount
    add((3, 1, 4, 0),  *_gauge(0))            # nvmeNamespaceTableRowCount
    add((3, 1, 7, 0),  *_gauge(0))            # nvmePowerStateTableRowCount
    add((3, 1, 10, 0), *_gauge(0))            # nvmeLbaFormatTableRowCount
    add((3, 1, 13, 0), *_gauge(n_nvme))       # nvmeHealthTableRowCount
    add((3, 1, 16, 0), *_gauge(0))            # nvmeSelfTestTableRowCount
    add((3, 1, 19, 0), *_gauge(0))            # nvmeErrorLogTableRowCount
    add((3, 1, 22, 0), *_gauge(0))            # nvmeCapabilityTableRowCount
    add((4, 1, 1, 0),  *_gauge(n_ata))        # sataInfoTableRowCount
    add((4, 1, 4, 0),  *_gauge(n_ata))        # sataHealthTableRowCount
    add((4, 1, 7, 0),  *_gauge(0))            # sataAttrTableRowCount
    add((4, 1, 10, 0), *_gauge(0))            # sataErrorLogTableRowCount
    add((4, 1, 13, 0), *_gauge(0))            # sataErrorCmdTableRowCount
    add((4, 1, 16, 0), *_gauge(0))            # sataSelfTestTableRowCount
    add((4, 1, 19, 0), *_gauge(0))            # sataErcTableRowCount
    add((4, 1, 22, 0), *_gauge(0))            # sataPhyEventTableRowCount
    add((4, 1, 25, 0), *_gauge(0))            # sataSelectiveTestTableRowCount
    add((4, 1, 32, 0), *_gauge(0))            # sataLogDirTableRowCount
    add((4, 1, 38, 0), *_gauge(0))            # sataDevStatTableRowCount
    add((4, 1, 41, 0), *_gauge(0))            # sataPendingDefectsTableRowCount
    add((5, 1, 4, 0),  *_gauge(n_sas))        # sasHealthTableRowCount
    add((5, 1, 7, 0),  *_gauge(n_sas * 2))    # sasErrorCounterTableRowCount
    add((6, 1, 1, 0),  *_gauge(0))            # sensorTableRowCount

    used_d_idx: set = set()
    n_sata_attrs         = 0
    n_sata_errorlog      = 0
    n_sata_errorcmd      = 0
    n_sata_selftest      = 0
    n_sata_erc           = 0
    n_sata_phyevent      = 0
    n_sata_selective     = 0
    n_sata_logdir        = 0
    n_sata_devstat       = 0
    n_sata_pending_def   = 0
    n_sensors            = 0
    n_nvme_ctrl          = 0
    n_nvme_ns            = 0
    n_nvme_ps            = 0
    n_nvme_lba           = 0
    n_nvme_st            = 0
    n_nvme_el            = 0
    n_nvme_cap           = 0
    first_ata            = True
    # per-device SATA row counts: {d_idx: {table_id: count}}
    sata_dev_counts: Dict[int, Dict[int, int]] = {}
    # per-device subindex groups for errorcmd/devstat: {(d_idx, table_id, sub): True}
    sata_dev_subidx: set = set()

    for dev in sorted(devices, key=lambda d: (d["serial_number"], d["model_name"])):
        d_idx = _device_index(dev, used_d_idx)
        used_d_idx.add(d_idx)

        _add_common_device(add, dev, d_idx)

        proto = dev["protocol"]
        if proto == "nvme":
            _add_nvme_health(add, dev, d_idx)
            n_nvme_ctrl += _add_nvme_controller(add, dev, d_idx)
            n_nvme_ns   += _add_nvme_namespaces(add, dev, d_idx)
            n_nvme_ps   += _add_nvme_power_states(add, dev, d_idx)
            n_nvme_lba  += _add_nvme_lba_formats(add, dev, d_idx)
            n_nvme_st   += _add_nvme_selftests(add, dev, d_idx)
            n_nvme_el   += _add_nvme_errlogs(add, dev, d_idx)
            n_nvme_cap  += _add_nvme_capability(add, dev, d_idx)
        elif proto in ("ata", "sat"):
            _add_sata_info(add, dev, d_idx)
            _add_sata_health(add, dev, d_idx)
            dc: Dict[int, int] = {}
            dc[1]  = 1                                                    # sata_info (1 row/device)
            dc[2]  = 1                                                    # sata_health (1 row/device)
            dc[3]  = _add_sata_attrs(add, dev, d_idx);         n_sata_attrs       += dc[3]
            dc[4]  = _add_sata_errorlog(add, dev, d_idx);      n_sata_errorlog    += dc[4]
            dc[5]  = _add_sata_errorcmd(add, dev, d_idx);      n_sata_errorcmd    += dc[5]
            dc[6]  = _add_sata_selftest(add, dev, d_idx);      n_sata_selftest    += dc[6]
            dc[7]  = _add_sata_erc(add, dev, d_idx);           n_sata_erc         += dc[7]
            dc[8]  = _add_sata_phyevent(add, dev, d_idx);      n_sata_phyevent    += dc[8]
            dc[9]  = _add_sata_selective(add, dev, d_idx, first_ata); n_sata_selective += dc[9]
            dc[10] = _add_sata_logdir(add, dev, d_idx, first_ata);    n_sata_logdir    += dc[10]
            dc[11] = _add_sata_devstat(add, dev, d_idx);       n_sata_devstat     += dc[11]
            dc[12] = _add_sata_pending_defects(add, dev, d_idx); n_sata_pending_def += dc[12]
            sata_dev_counts[d_idx] = dc
            # Record subindexes for BySubindex table
            el = ((dev["raw"].get("ata_smart_error_log") or {}).get("extended") or {}).get("table") or []
            for i in range(len(el)):
                sata_dev_subidx.add((d_idx, 5, i + 1))    # errorcmd: subindex = error entry index
            for pg in (dev["raw"].get("ata_device_statistics") or {}).get("pages") or []:
                sata_dev_subidx.add((d_idx, 11, int(pg.get("number", 0) or 0)))  # devstat: subindex = page num
            first_ata = False
        elif proto in ("scsi", "sas"):
            _add_sas_health(add, dev, d_idx)
            _add_sas_error_counters(add, dev, d_idx)

        n_sensors += _add_sensors(add, dev, d_idx)

    # Patch count scalars computed during the device loop
    _PATCH = {
        _full((3, 1, 1, 0)),  _full((3, 1, 4, 0)),  _full((3, 1, 7, 0)),
        _full((3, 1, 10, 0)), _full((3, 1, 16, 0)), _full((3, 1, 19, 0)),
        _full((3, 1, 22, 0)),
        _full((4, 1, 7, 0)),  _full((4, 1, 10, 0)), _full((4, 1, 13, 0)),
        _full((4, 1, 16, 0)), _full((4, 1, 19, 0)), _full((4, 1, 22, 0)),
        _full((4, 1, 25, 0)), _full((4, 1, 32, 0)), _full((4, 1, 38, 0)),
        _full((4, 1, 41, 0)),
        _full((6, 1, 1, 0)),
    }
    entries[:] = [e for e in entries if e[0] not in _PATCH]
    add((3, 1, 1, 0),  *_gauge(n_nvme_ctrl))
    add((3, 1, 4, 0),  *_gauge(n_nvme_ns))
    add((3, 1, 7, 0),  *_gauge(n_nvme_ps))
    add((3, 1, 10, 0), *_gauge(n_nvme_lba))
    add((3, 1, 16, 0), *_gauge(n_nvme_st))
    add((3, 1, 19, 0), *_gauge(n_nvme_el))
    add((3, 1, 22, 0), *_gauge(n_nvme_cap))
    add((4, 1, 7, 0),  *_gauge(n_sata_attrs))
    add((4, 1, 10, 0), *_gauge(n_sata_errorlog))
    add((4, 1, 13, 0), *_gauge(n_sata_errorcmd))
    add((4, 1, 16, 0), *_gauge(n_sata_selftest))
    add((4, 1, 19, 0), *_gauge(n_sata_erc))
    add((4, 1, 22, 0), *_gauge(n_sata_phyevent))
    add((4, 1, 25, 0), *_gauge(n_sata_selective))
    add((4, 1, 32, 0), *_gauge(n_sata_logdir))
    add((4, 1, 38, 0), *_gauge(n_sata_devstat))
    add((4, 1, 41, 0), *_gauge(n_sata_pending_def))
    add((6, 1, 1, 0),  *_gauge(n_sensors))
    # Ensure per-device scalar defaults exist even when no ATA devices present
    if first_ata:   # no ATA device was processed
        for sfx in ((4, 1, 28, 0), (4, 1, 29, 0), (4, 1, 31, 0)):
            add(sfx, *_gauge(0))
        for sfx in ((4, 1, 30, 0), (4, 1, 37, 0)):
            add(sfx, *_integer(2))  # TruthValue false
        for sfx in ((4, 1, 35, 0), (4, 1, 36, 0)):
            add(sfx, *_gauge(0))

    # Build smartSATAChanges subtree
    total_sata_counts = {
        1: n_ata, 2: n_ata, 3: n_sata_attrs, 4: n_sata_errorlog,
        5: n_sata_errorcmd, 6: n_sata_selftest, 7: n_sata_erc,
        8: n_sata_phyevent, 9: n_sata_selective, 10: n_sata_logdir,
        11: n_sata_devstat, 12: n_sata_pending_def,
    }
    _add_sata_changes(add, sata_dev_counts, sata_dev_subidx, ts, total_sata_counts)

    # ---- Fingerprint tables; advance LastChange only when content changes ----
    _LC_MAP = {
        "device":               (2, 1, 2, 0),
        "nvme_controller":      (3, 1, 2, 0),
        "nvme_namespace":       (3, 1, 5, 0),
        "nvme_power_state":     (3, 1, 8, 0),
        "nvme_lba_format":      (3, 1, 11, 0),
        "nvme_health":          (3, 1, 14, 0),
        "nvme_selftest":        (3, 1, 17, 0),
        "nvme_errlog":          (3, 1, 20, 0),
        "nvme_capability":      (3, 1, 23, 0),
        "sata_health":          (4, 1, 5, 0),
        "sata_attr":            (4, 1, 8, 0),
        "sata_errorlog":        (4, 1, 11, 0),
        "sata_errorcmd":        (4, 1, 14, 0),
        "sata_selftest":        (4, 1, 17, 0),
        "sata_erc":             (4, 1, 20, 0),
        "sata_phyevent":        (4, 1, 23, 0),
        "sata_selective":       (4, 1, 26, 0),
        "sata_logdir":          (4, 1, 33, 0),
        "sata_devstat":         (4, 1, 39, 0),
        "sata_pending_defects": (4, 1, 42, 0),
        "sas_health":           (5, 1, 5, 0),
        "sas_err":              (5, 1, 8, 0),
        "sensor":               (6, 1, 2, 0),
    }
    for tname, lc_suffix in _LC_MAP.items():
        fp = _table_fingerprint(entries, _TABLE_PREFIXES[tname])
        if fp != _st.checksums.get(tname):
            _st.checksums[tname]  = fp
            _st.timestamps[tname] = ts
            LOGGER.notice("table %s changed (fp %08x)", tname, fp & 0xFFFFFFFF)
        add(lc_suffix, "datetimeval", _st.timestamps.get(tname, ts))

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
    add(T+(2,  d_idx, hi), *_bits(h["critical_warning"], nbits=6))
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
    st_log = dev["raw"].get("nvme_self_test_log") or {}
    cur_st = st_log.get("current_self_test") or {}
    cur_code = cur_st.get("code") or {}
    st_val = int(cur_code.get("value", 0))
    st_str = "" if st_val == 0 else str(cur_code.get("string") or "")
    add(T+(22, d_idx, hi), *_gauge(st_val))
    add(T+(23, d_idx, hi), *_string(st_str))


# --------------------------------------------------------------------------
# NVMe controller table  (.3.1.3.1)
# --------------------------------------------------------------------------

def _add_nvme_controller(add, dev: dict, d_idx: int) -> int:
    T   = (3, 1, 3, 1)
    raw = dev["raw"]
    ci  = 1   # single controller per device
    pv  = raw.get("nvme_pci_vendor") or {}
    vid = int(pv.get("id", 0))
    sid = int(pv.get("subsystem_id", 0))
    ver = raw.get("nvme_version") or {}
    add(T+(1,  d_idx, ci), *_gauge(vid))
    add(T+(2,  d_idx, ci), *_gauge(int(raw.get("nvme_ieee_oui_identifier", 0) or 0)))
    add(T+(3,  d_idx, ci), *_counter64(int(raw.get("nvme_total_capacity", 0) or 0)))
    add(T+(4,  d_idx, ci), *_counter64(int(raw.get("nvme_unallocated_capacity", 0) or 0)))
    add(T+(5,  d_idx, ci), *_gauge(int(raw.get("nvme_controller_id", 0) or 0)))
    add(T+(6,  d_idx, ci), *_string(str(ver.get("string", "") or "")))
    add(T+(7,  d_idx, ci), *_gauge(int(raw.get("nvme_number_of_namespaces", 0) or 0)))
    add(T+(8,  d_idx, ci), *_gauge(int(raw.get("nvme_maximum_data_transfer_pages", 0) or 0)))
    add(T+(12, d_idx, ci), *_gauge(sid))
    add(T+(13, d_idx, ci), *_gauge(int(ver.get("value", 0) or 0)))
    add(T+(14, d_idx, ci), *_string(_pci_vendor_name(vid)))
    add(T+(15, d_idx, ci), *_string(_pci_vendor_name(sid)))
    return 1


def _eui64_text(eui64) -> str:
    """Format smartctl EUI-64 dict {'oui': int, 'ext_id': int} as xx:xx:xx:xx:xx:xx:xx:xx."""
    if not isinstance(eui64, dict):
        return ""
    oui    = int(eui64.get("oui", 0) or 0)
    ext_id = int(eui64.get("ext_id", 0) or 0)
    val    = (oui << 40) | ext_id
    return ":".join(f"{b:02x}" for b in val.to_bytes(8, "big"))


def _nguid_text(nguid) -> str:
    """Format smartctl NGUID dict {'ms': int, 'ext_id': int} as 16 hex octets."""
    if not isinstance(nguid, dict):
        return ""
    ms     = int(nguid.get("ms", 0) or 0)
    ext_id = int(nguid.get("ext_id", 0) or 0)
    val    = (ms << 64) | ext_id
    return ":".join(f"{b:02x}" for b in val.to_bytes(16, "big"))


# --------------------------------------------------------------------------
# NVMe namespace table  (.3.1.6.1)
# --------------------------------------------------------------------------

def _add_nvme_namespaces(add, dev: dict, d_idx: int) -> int:
    T   = (3, 1, 6, 1)
    raw = dev["raw"]
    namespaces = raw.get("nvme_namespaces") or []
    for ns in namespaces:
        ns_id = int(ns.get("id", 0))
        size  = ns.get("size") or {}
        cap   = ns.get("capacity") or {}
        util  = ns.get("utilization") or {}
        add(T+(1,  d_idx, ns_id), *_gauge(ns_id))
        add(T+(2,  d_idx, ns_id), *_counter64(int(size.get("bytes", 0) or 0)))
        add(T+(3,  d_idx, ns_id), *_counter64(int(cap.get("bytes", 0) or 0)))
        add(T+(4,  d_idx, ns_id), *_counter64(int(util.get("bytes", 0) or 0)))
        add(T+(5,  d_idx, ns_id), *_gauge(int(ns.get("formatted_lba_size", 0) or 0)))
        add(T+(6,  d_idx, ns_id), *_string(_eui64_text(ns.get("eui64"))))
        add(T+(7,  d_idx, ns_id), *_string(_nguid_text(ns.get("nguid"))))
        add(T+(8,  d_idx, ns_id), *_counter64(int(size.get("blocks", 0) or 0)))
        add(T+(9,  d_idx, ns_id), *_counter64(int(cap.get("blocks", 0) or 0)))
        add(T+(10, d_idx, ns_id), *_counter64(int(util.get("blocks", 0) or 0)))
    return len(namespaces)


# --------------------------------------------------------------------------
# NVMe power state table  (.3.1.9.1)
# --------------------------------------------------------------------------

def _add_nvme_power_states(add, dev: dict, d_idx: int) -> int:
    T      = (3, 1, 9, 1)
    raw    = dev["raw"]
    states = raw.get("nvme_power_states") or []
    for ps_id, ps in enumerate(states):
        mp  = ps.get("max_power") or {}
        upw = int(mp.get("units_per_watt", 1) or 1)
        mw  = int(mp.get("value", 0) or 0) * 1000 // upw
        operational = not bool(ps.get("non_operational_state", False))
        add(T+(2,  d_idx, ps_id), *_integer(1 if operational else 2))   # TruthValue
        add(T+(3,  d_idx, ps_id), *_gauge(mw))
        add(T+(6,  d_idx, ps_id), *_gauge(int(ps.get("relative_read_latency", 0) or 0)))
        add(T+(7,  d_idx, ps_id), *_gauge(int(ps.get("relative_read_throughput", 0) or 0)))
        add(T+(8,  d_idx, ps_id), *_gauge(int(ps.get("relative_write_latency", 0) or 0)))
        add(T+(9,  d_idx, ps_id), *_gauge(int(ps.get("relative_write_throughput", 0) or 0)))
        add(T+(10, d_idx, ps_id), *_gauge(int(ps.get("entry_latency_us", 0) or 0)))
        add(T+(11, d_idx, ps_id), *_gauge(int(ps.get("exit_latency_us", 0) or 0)))
    return len(states)


# --------------------------------------------------------------------------
# NVMe LBA format table  (.3.1.12.1)  INDEX { deviceIndex, namespaceId, lbaFormatId }
# --------------------------------------------------------------------------

def _add_nvme_lba_formats(add, dev: dict, d_idx: int) -> int:
    T     = (3, 1, 12, 1)
    raw   = dev["raw"]
    count = 0
    for ns in (raw.get("nvme_namespaces") or []):
        ns_id = int(ns.get("id", 0))
        for fmt_id, fmt in enumerate(ns.get("lba_formats") or []):
            current = 1 if fmt.get("formatted") else 2
            add(T+(2, d_idx, ns_id, fmt_id), *_integer(current))
            add(T+(3, d_idx, ns_id, fmt_id), *_gauge(int(fmt.get("data_bytes", 0) or 0)))
            add(T+(4, d_idx, ns_id, fmt_id), *_gauge(int(fmt.get("metadata_bytes", 0) or 0)))
            add(T+(5, d_idx, ns_id, fmt_id), *_gauge(int(fmt.get("relative_performance", 0) or 0)))
            count += 1
    return count


# --------------------------------------------------------------------------
# NVMe self-test log table  (.3.1.18.1)
# --------------------------------------------------------------------------

_NVME_ST_TYPE = {1: 1, 2: 2, 14: 255}   # short, extended, vendor-specific

def _add_nvme_selftests(add, dev: dict, d_idx: int) -> int:
    T       = (3, 1, 18, 1)
    raw     = dev["raw"]
    st_log  = raw.get("nvme_self_test_log") or {}
    entries = st_log.get("table") or []
    for i, e in enumerate(entries):
        st_idx  = i + 1
        code    = e.get("self_test_code") or {}
        result  = e.get("self_test_result") or {}
        st_type = _NVME_ST_TYPE.get(int(code.get("value", 0)), 255)
        add(T+(2,  d_idx, st_idx), *_gauge(st_idx))
        add(T+(3,  d_idx, st_idx), *_integer(st_type))
        add(T+(4,  d_idx, st_idx), *_integer(int(result.get("value", 0) or 0)))
        add(T+(5,  d_idx, st_idx), *_string(str(result.get("string") or "")))
        add(T+(6,  d_idx, st_idx), *_counter64(int(e.get("power_on_hours", 0) or 0)))
        add(T+(7,  d_idx, st_idx), *_counter64(int(e.get("failing_lba", 0) or 0) & 0xFFFFFFFFFFFFFFFF))
        add(T+(8,  d_idx, st_idx), *_gauge(int(e.get("nsid", 0) or 0) & 0xFFFFFFFF))
        add(T+(9,  d_idx, st_idx), *_gauge(int(e.get("segment_number", 0) or 0)))
        add(T+(10, d_idx, st_idx), *_gauge(int(e.get("status_code_type", 0) or 0)))
        add(T+(11, d_idx, st_idx), *_gauge(int(e.get("status_code", 0) or 0)))
    return len(entries)


# --------------------------------------------------------------------------
# NVMe error log table  (.3.1.21.1)
# --------------------------------------------------------------------------

def _add_nvme_errlogs(add, dev: dict, d_idx: int) -> int:
    T       = (3, 1, 21, 1)
    raw     = dev["raw"]
    el      = raw.get("nvme_error_information_log") or {}
    entries = el.get("table") or []
    poll_ts = dev.get("poll_time") or datetime.now(timezone.utc)
    for i, e in enumerate(entries):
        el_idx = i + 1
        sf = e.get("status_field") or {}
        lba_v = (e.get("lba") or {}).get("value", 0)
        add(T+(2,  d_idx, el_idx), *_counter64(int(e.get("error_count", 0) or 0)))
        add(T+(3,  d_idx, el_idx), *_gauge(int(e.get("submission_queue_id", 0) or 0)))
        add(T+(4,  d_idx, el_idx), *_gauge(int(e.get("command_id", 0) or 0)))
        add(T+(5,  d_idx, el_idx), *_gauge(int(sf.get("value", 0) or 0)))
        add(T+(6,  d_idx, el_idx), *_gauge(int(e.get("parameter_error_location", 0) or 0)))
        add(T+(7,  d_idx, el_idx), *_counter64(int(lba_v or 0) & 0xFFFFFFFFFFFFFFFF))
        add(T+(8,  d_idx, el_idx), *_gauge(int(e.get("nsid", 0) or 0)))
        add(T+(9,  d_idx, el_idx), *_gauge(0))   # vendor_specific_info — not in smartd state
        add(T+(10, d_idx, el_idx), *_gauge(int(sf.get("status_code", 0) or 0)))
        add(T+(11, d_idx, el_idx), *_gauge(int(sf.get("status_code_type", 0) or 0)))
        add(T+(12, d_idx, el_idx), *_integer(2 if not sf.get("do_not_retry") else 1))
        add(T+(13, d_idx, el_idx), *_string(str(sf.get("string") or "")))
        add(T+(14, d_idx, el_idx), *_integer(2 if not sf.get("phase_tag") else 1))
        add(T+(15, d_idx, el_idx), *_datetimeval(poll_ts))
    return len(entries)


# --------------------------------------------------------------------------
# NVMe capability table  (.3.1.24.1)
# --------------------------------------------------------------------------

def _nvme_cap_text(section: dict, bits: list) -> str:
    """Join labels for all true boolean flags in a smartctl capability section."""
    return ", ".join(label for key, label in bits if section.get(key))


_ADM_BITS = [
    ("security_send_receive",        "Security Send/Receive"),
    ("format_nvm",                   "Format NVM"),
    ("firmware_download",            "Firmware Download"),
    ("namespace_management",         "Namespace Management"),
    ("self_test",                    "Self-test"),
    ("directives",                   "Directives"),
    ("mi_send_receive",              "MI Send/Receive"),
    ("virtualization_management",    "Virtualization Management"),
    ("doorbell_buffer_config",       "Doorbell Buffer Config"),
    ("get_lba_status",               "Get LBA Status"),
    ("command_and_feature_lockdown", "Command and Feature Lockdown"),
]
_NVM_BITS = [
    ("compare",                     "Compare"),
    ("write_uncorrectable",         "Write Uncorrectable"),
    ("dataset_management",          "Dataset Management"),
    ("write_zeroes",                "Write Zeroes"),
    ("save_select_feature_nonzero", "Save/Select Feature Nonzero"),
    ("reservations",                "Reservations"),
    ("timestamp",                   "Timestamp"),
    ("verify",                      "Verify"),
    ("copy",                        "Copy"),
]
_LPA_BITS = [
    ("smart_health_per_namespace", "SMART/Health per Namespace"),
    ("commands_effects_log",       "Commands Effects Log"),
    ("extended_get_log_page_cmd",  "Extended Get Log Page"),
    ("telemetry_log",              "Telemetry Log"),
    ("persistent_event_log",       "Persistent Event Log"),
    ("supported_log_pages_log",    "Supported Log Pages Log"),
    ("telemetry_data_area_4",      "Telemetry Data Area 4"),
]


def _add_nvme_capability(add, dev: dict, d_idx: int) -> int:
    T   = (3, 1, 24, 1)
    raw = dev["raw"]
    ci  = 1
    fw  = raw.get("nvme_firmware_update_capabilities") or {}
    adm = raw.get("nvme_optional_admin_commands") or {}
    nvm = raw.get("nvme_optional_nvm_commands") or {}
    lpa = raw.get("nvme_log_page_attributes") or {}
    add(T+(1, d_idx, ci), *_gauge(int(fw.get("value", 0) or 0)))
    add(T+(2, d_idx, ci), *_gauge(int(fw.get("slots", 0) or 0)))
    add(T+(3, d_idx, ci), *_integer(2 if fw.get("activation_without_reset") else 1))
    add(T+(4, d_idx, ci), *_gauge(int(adm.get("value", 0) or 0)))
    add(T+(5, d_idx, ci), *_gauge(int(nvm.get("value", 0) or 0)))
    add(T+(6, d_idx, ci), *_gauge(int(lpa.get("value", 0) or 0)))
    add(T+(7, d_idx, ci), *_string(_nvme_cap_text(adm, _ADM_BITS)))
    add(T+(8, d_idx, ci), *_string(_nvme_cap_text(nvm, _NVM_BITS)))
    add(T+(9, d_idx, ci), *_string(_nvme_cap_text(lpa, _LPA_BITS)))
    return 1


# --------------------------------------------------------------------------
# SATA info table  (.4.1.3.1)
# --------------------------------------------------------------------------

def _parse_sata_info(raw: dict) -> dict:
    ata_ver  = raw.get("ata_version") or {}
    sata_ver = raw.get("sata_version") or {}
    ff       = raw.get("form_factor") or {}
    uc       = raw.get("user_capacity") or {}
    ss       = raw.get("smart_support") or {}
    trim     = raw.get("trim") or {}
    ispd     = raw.get("interface_speed") or {}
    ispd_max = ispd.get("max") or {}
    ispd_cur = ispd.get("current") or {}
    apm      = raw.get("ata_apm") or {}
    rla      = raw.get("read_lookahead") or {}
    wc       = raw.get("write_cache") or {}
    sec      = raw.get("ata_security") or {}
    attrs    = raw.get("ata_smart_attributes") or {}
    sdata    = raw.get("ata_smart_data") or {}
    offl     = sdata.get("offline_data_collection") or {}
    st_poll  = (sdata.get("self_test") or {}).get("polling_minutes") or {}
    caps     = sdata.get("capabilities") or {}
    err_log  = (raw.get("ata_smart_error_log") or {}).get("extended") or {}
    st_log   = (raw.get("ata_smart_self_test_log") or {}).get("extended") or {}
    pdef     = raw.get("ata_pending_defects_log") or {}
    sct_cap  = raw.get("ata_sct_capabilities") or {}
    sct_hist = (raw.get("ata_sct_temperature_history") or {}).get("temperature") or {}
    return {
        "ata_version":           _msb_pos(int(ata_ver.get("major_value", 0) or 0)),
        "sata_version":          _sata_ver_enum(int(sata_ver.get("value", 0) or 0)),
        "rotation_rate":         int(raw.get("rotation_rate", 0) or 0),
        "form_factor":           int(ff.get("ata_value", 0) or 0),
        "logical_block_size":    int(raw.get("logical_block_size", 0) or 0),
        "physical_block_size":   int(raw.get("physical_block_size", 0) or 0),
        "user_capacity_bytes":   int(uc.get("bytes", 0) or 0),
        "user_capacity_blocks":  int(uc.get("blocks", 0) or 0),
        "in_smartctl_db":        bool(raw.get("in_smartctl_database", False)),
        "smart_available":       bool(ss.get("available", False)),
        "smart_enabled":         bool(ss.get("enabled", False)),
        "trim_supported":        bool(trim.get("supported", False)),
        "ata_version_major":     int(ata_ver.get("major_value", 0) or 0),
        "ata_version_minor":     int(ata_ver.get("minor_value", 0) or 0),
        "if_speed_max":          _if_speed_mbps(ispd_max),
        "if_speed_current":      _if_speed_mbps(ispd_cur),
        "apm_enabled":           bool(apm.get("enabled", False)),
        "apm_level":             int(apm.get("level", 0) or 0),
        "read_lookahead":        bool(rla.get("enabled", False)),
        "write_cache":           bool(wc.get("enabled", False)),
        "security_state":        int(sec.get("state", 0) or 0),
        "security_enabled":      bool(sec.get("enabled", False)),
        "security_frozen":       bool(sec.get("frozen", False)),
        "attr_revision":         int(attrs.get("revision", 0) or 0),
        "offline_completion_secs": int(offl.get("completion_seconds", 0) or 0),
        "polling_short":         int(st_poll.get("short", 0) or 0),
        "polling_extended":      int(st_poll.get("extended", 0) or 0),
        "polling_conveyance":    int(st_poll.get("conveyance", 0) or 0),
        "cap_selftests":         bool(caps.get("self_tests_supported", False)),
        "cap_conveyance":        bool(caps.get("conveyance_self_test_supported", False)),
        "cap_selective":         bool(caps.get("selective_self_test_supported", False)),
        "cap_error_logging":     bool(caps.get("error_logging_supported", False)),
        "cap_gp_logging":        bool(caps.get("gp_logging_supported", False)),
        "cap_exec_offline_immediate": bool(caps.get("exec_offline_immediate_supported", False)),
        "cap_offline_aborted_on_cmd": bool(caps.get("offline_is_aborted_upon_new_cmd", False)),
        "cap_offline_surface_scan":   bool(caps.get("offline_surface_scan_supported", False)),
        "error_log_revision":    int(err_log.get("revision", 0) or 0),
        "error_log_sectors":     int(err_log.get("sectors", 0) or 0),
        "selftest_log_revision": int(st_log.get("revision", 0) or 0),
        "selftest_log_sectors":  int(st_log.get("sectors", 0) or 0),
        "pending_defects_size":  int(pdef.get("size", 0) or 0),
        "cap_attr_autosave":     bool(caps.get("attribute_autosave_enabled", False)),
        "sct_error_recovery":    bool(sct_cap.get("error_recovery_control_supported", False)),
        "sct_feature_control":   bool(sct_cap.get("feature_control_supported", False)),
        "sct_data_table":        bool(sct_cap.get("data_table_supported", False)),
        "sct_hist_op_limit_min": int(sct_hist.get("op_limit_min", 0) or 0),
        "sct_hist_op_limit_max": int(sct_hist.get("op_limit_max", 0) or 0),
        "sct_hist_limit_min":    int(sct_hist.get("limit_min", 0) or 0),
        "sct_hist_limit_max":    int(sct_hist.get("limit_max", 0) or 0),
    }


def _add_sata_info(add, dev: dict, d_idx: int) -> None:
    T = (4, 1, 3, 1)
    i = _parse_sata_info(dev["raw"])
    add(T+(1,  d_idx), *_integer(i["ata_version"]))
    add(T+(2,  d_idx), *_integer(i["sata_version"]))
    add(T+(3,  d_idx), *_gauge(i["rotation_rate"]))
    add(T+(4,  d_idx), *_integer(i["form_factor"]))
    add(T+(5,  d_idx), *_gauge(i["logical_block_size"]))
    add(T+(6,  d_idx), *_gauge(i["physical_block_size"]))
    add(T+(7,  d_idx), *_counter64(i["user_capacity_bytes"]))
    add(T+(8,  d_idx), *_truthvalue(i["in_smartctl_db"]))
    add(T+(9,  d_idx), *_truthvalue(i["smart_available"]))
    add(T+(10, d_idx), *_truthvalue(i["smart_enabled"]))
    add(T+(11, d_idx), *_truthvalue(i["trim_supported"]))
    add(T+(12, d_idx), *_counter64(i["user_capacity_blocks"]))
    add(T+(13, d_idx), *_gauge(i["ata_version_major"]))
    add(T+(14, d_idx), *_gauge(i["ata_version_minor"]))
    add(T+(15, d_idx), *_gauge(i["if_speed_max"]))
    add(T+(16, d_idx), *_gauge(i["if_speed_current"]))
    add(T+(17, d_idx), *_truthvalue(i["apm_enabled"]))
    add(T+(18, d_idx), *_integer(i["apm_level"]))
    add(T+(19, d_idx), *_truthvalue(i["read_lookahead"]))
    add(T+(20, d_idx), *_truthvalue(i["write_cache"]))
    add(T+(21, d_idx), *_gauge(i["security_state"]))
    add(T+(22, d_idx), *_truthvalue(i["security_enabled"]))
    add(T+(23, d_idx), *_truthvalue(i["security_frozen"]))
    add(T+(24, d_idx), *_gauge(i["attr_revision"]))
    add(T+(25, d_idx), *_gauge(i["offline_completion_secs"]))
    add(T+(26, d_idx), *_gauge(i["polling_short"]))
    add(T+(27, d_idx), *_gauge(i["polling_extended"]))
    add(T+(28, d_idx), *_gauge(i["polling_conveyance"]))
    add(T+(29, d_idx), *_truthvalue(i["cap_selftests"]))
    add(T+(30, d_idx), *_truthvalue(i["cap_conveyance"]))
    add(T+(31, d_idx), *_truthvalue(i["cap_selective"]))
    add(T+(32, d_idx), *_truthvalue(i["cap_error_logging"]))
    add(T+(33, d_idx), *_truthvalue(i["cap_gp_logging"]))
    add(T+(40, d_idx), *_truthvalue(i["cap_exec_offline_immediate"]))
    add(T+(41, d_idx), *_truthvalue(i["cap_offline_aborted_on_cmd"]))
    add(T+(42, d_idx), *_truthvalue(i["cap_offline_surface_scan"]))
    add(T+(50, d_idx), *_gauge(i["error_log_revision"]))
    add(T+(51, d_idx), *_gauge(i["error_log_sectors"]))
    add(T+(52, d_idx), *_gauge(i["selftest_log_revision"]))
    add(T+(53, d_idx), *_gauge(i["selftest_log_sectors"]))
    add(T+(54, d_idx), *_gauge(i["pending_defects_size"]))
    add(T+(55, d_idx), *_truthvalue(i["cap_attr_autosave"]))
    add(T+(60, d_idx), *_truthvalue(i["sct_error_recovery"]))
    add(T+(61, d_idx), *_truthvalue(i["sct_feature_control"]))
    add(T+(62, d_idx), *_truthvalue(i["sct_data_table"]))
    add(T+(63, d_idx), *_integer(i["sct_hist_op_limit_min"]))
    add(T+(64, d_idx), *_integer(i["sct_hist_op_limit_max"]))
    add(T+(65, d_idx), *_integer(i["sct_hist_limit_min"]))
    add(T+(66, d_idx), *_integer(i["sct_hist_limit_max"]))


# --------------------------------------------------------------------------
# SATA health table  (.4.1.6.1)
# --------------------------------------------------------------------------

def _parse_sata_health(raw: dict) -> dict:
    ata  = raw.get("ata_smart_data") or {}
    offl = ata.get("offline_data_collection") or {}
    st   = ata.get("self_test") or {}
    offl_val    = int((offl.get("status") or {}).get("value", 0))
    st_val      = int((st.get("status") or {}).get("value", 0))
    remaining_pct = int((st.get("status") or {}).get("remaining_percent", 0) or 0)
    pm          = st.get("polling_minutes") or {}
    err_log     = (raw.get("ata_smart_error_log") or {}).get("extended") or {}
    st_log_ext  = (raw.get("ata_smart_self_test_log") or {}).get("extended") or {}
    sct         = raw.get("ata_sct_status") or {}
    sct_temp = sct.get("temperature") or {}
    pot = raw.get("power_on_time") or {}
    return {
        "power_on_hours":          int(pot.get("hours", 0)),
        "power_cycles":            int(raw.get("power_cycle_count", 0) or 0),
        "offline_status":          offl_val,
        "selftest_exec_status":    _SELFTEST_EXEC_STATUS.get((st_val >> 4) & 0xF, 0),
        "selftest_exec_remaining": (st_val & 0xF) * 10,
        "selftest_remaining_pct":  remaining_pct,
        "selftest_polling_min":    pm,
        "selftest_log_first_type": int(((st_log_ext.get("table") or [{}])[0].get("type") or {}).get("value", 0)),
        "user_capacity_bytes":     int((raw.get("user_capacity") or {}).get("bytes", 0) or 0),
        "error_log_count":         int(err_log.get("count", 0) or 0),
        "pending_defects_count":   int((raw.get("ata_pending_defects_log") or {}).get("count", 0) or 0),
        "selftest_log_count":      int(st_log_ext.get("count", 0) or 0),
        "selftest_log_err_total":  int(st_log_ext.get("error_count_total", 0) or 0),
        "selftest_log_err_outdated": int(st_log_ext.get("error_count_outdated", 0) or 0),
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


def _update_selftest_progress(d_idx: int, h: dict):
    """Track selftest scan rate across polls; return (estimated_completion_ts, estimated_bytes_sec)."""
    remaining_pct = h["selftest_remaining_pct"]
    if remaining_pct == 0:
        _st.selftest_progress.pop(d_idx, None)
        return 0, 0

    now_ns  = time.time_ns()
    prog    = _st.selftest_progress.get(d_idx)
    is_new  = prog is None

    if is_new:
        # Determine polling_min from most recent selftest log entry type
        pm   = h["selftest_polling_min"]
        ftype = h["selftest_log_first_type"]
        polling_min = int(pm.get({1: "short", 2: "extended", 3: "conveyance"}.get(ftype, ""), 0)
                         or pm.get("extended", 0) or 0)
        est = (time.time() + polling_min * 60) if (polling_min and remaining_pct == 90) else 0
        prog = {"start_ns": now_ns, "last_remaining": remaining_pct,
                "polling_min": polling_min, "estimated_completion": est}
        _st.selftest_progress[d_idx] = prog
    elif remaining_pct < prog["last_remaining"]:
        # Falling edge: measured rate available
        elapsed_ns = now_ns - prog["start_ns"]
        pct_done   = 100 - remaining_pct
        if elapsed_ns > 0 and pct_done > 0:
            remaining_ns = elapsed_ns * remaining_pct // pct_done
            prog["estimated_completion"] = time.time() + remaining_ns / 1e9
        prog["last_remaining"] = remaining_pct

    est_completion = prog["estimated_completion"]
    polling_min    = prog["polling_min"]
    cap            = h["user_capacity_bytes"]
    est_bytes_sec  = (cap // (polling_min * 60)) if (polling_min and cap) else 0
    return est_completion, est_bytes_sec


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
    add(T+(7,  d_idx), *_gauge(h["pending_defects_count"]))
    add(T+(8,  d_idx), *_gauge(h["selftest_log_count"]))
    add(T+(9,  d_idx), *_gauge(h["selftest_log_err_total"]))
    add(T+(10, d_idx), *_gauge(h["selftest_log_err_outdated"]))
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
    # cols 22-23: estimated completion — track scan rate across polls
    est_completion, est_bytes_sec = _update_selftest_progress(d_idx, h)
    add(T+(22, d_idx), *_datetimeval(datetime.fromtimestamp(est_completion) if est_completion else None))
    add(T+(23, d_idx), *_counter64(est_bytes_sec))


# --------------------------------------------------------------------------
# SATA attribute table  (.4.1.9.1)
# --------------------------------------------------------------------------

def _parse_raw_value(raw_a: dict) -> int:
    raw_str = str(raw_a.get("string") or "").strip()
    m = re.match(r'^(\d+)', raw_str)
    return int(m.group(1)) if m else int(raw_a.get("value", 0) or 0)


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
            "raw_value":   _parse_raw_value(raw_a),
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
        add(T+(3,  d_idx, ai), *_bits(a["flags_value"], nbits=6))
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
# SATA error log table  (.4.1.12.1)
# --------------------------------------------------------------------------

def _add_sata_errorlog(add, dev: dict, d_idx: int) -> int:
    T       = (4, 1, 12, 1)
    entries = ((dev["raw"].get("ata_smart_error_log") or {}).get("extended") or {}).get("table") or []
    for i, e in enumerate(entries):
        ei   = i + 1
        comp = e.get("completion_registers") or {}
        lba  = int(comp.get("lba", 0) or 0)
        add(T+(2,  d_idx, ei), *_gauge(int(e.get("error_number", 0) or 0)))
        add(T+(3,  d_idx, ei), *_counter64(int(e.get("lifetime_hours", 0) or 0)))
        add(T+(4,  d_idx, ei), *_string(str(e.get("error_description") or "")))
        add(T+(5,  d_idx, ei), *_gauge(int(comp.get("error", 0) or 0)))
        add(T+(6,  d_idx, ei), *_gauge(int(comp.get("status", 0) or 0)))
        add(T+(7,  d_idx, ei), *_counter64(lba & 0xFFFFFFFFFFFFFFFF))
        add(T+(8,  d_idx, ei), *_gauge(int(comp.get("command", 0) or 0)))
        add(T+(9,  d_idx, ei), *_gauge(int(comp.get("count", 0) or 0)))
        add(T+(10, d_idx, ei), *_gauge(int(comp.get("device", 0) or 0)))
        add(T+(11, d_idx, ei), *_gauge(int(comp.get("features", 0) or 0)))
        add(T+(12, d_idx, ei), *_integer(int((e.get("device_state") or {}).get("value", 0) or 0) & 0xF))
    return len(entries)


# --------------------------------------------------------------------------
# SATA error cmd table  (.4.1.15.1)
# --------------------------------------------------------------------------

def _add_sata_errorcmd(add, dev: dict, d_idx: int) -> int:
    T       = (4, 1, 15, 1)
    entries = ((dev["raw"].get("ata_smart_error_log") or {}).get("extended") or {}).get("table") or []
    count   = 0
    for i, e in enumerate(entries):
        ei   = i + 1
        comp = e.get("completion_registers") or {}
        comp_error = int(comp.get("error", 0) or 0)
        for j, cmd in enumerate(e.get("previous_commands") or []):
            ci   = j + 1
            regs = cmd.get("registers") or {}
            lba  = int(regs.get("lba", 0) or 0)
            add(T+(2,  d_idx, ei, ci), *_gauge(int(regs.get("command", 0) or 0)))
            add(T+(3,  d_idx, ei, ci), *_gauge(int(regs.get("count", 0) or 0)))
            add(T+(4,  d_idx, ei, ci), *_gauge(int(regs.get("device", 0) or 0)))
            add(T+(5,  d_idx, ei, ci), *_gauge(comp_error))
            add(T+(6,  d_idx, ei, ci), *_gauge(int(regs.get("features", 0) or 0)))
            add(T+(7,  d_idx, ei, ci), *_counter64(lba & 0xFFFFFFFFFFFFFFFF))
            add(T+(8,  d_idx, ei, ci), *_gauge(0))   # reg_status reserved
            add(T+(9,  d_idx, ei, ci), *_gauge(int(cmd.get("powerup_milliseconds", 0) or 0)))
            add(T+(10, d_idx, ei, ci), *_string(str(cmd.get("command_name") or "")))
            count += 1
    return count


# --------------------------------------------------------------------------
# SATA self-test log table  (.4.1.18.1)
# --------------------------------------------------------------------------

_SATA_ST_TYPE = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 9: 9}   # map raw type value

def _add_sata_selftest(add, dev: dict, d_idx: int) -> int:
    T       = (4, 1, 18, 1)
    entries = ((dev["raw"].get("ata_smart_self_test_log") or {}).get("extended") or {}).get("table") or []
    for i, e in enumerate(entries):
        si     = i + 1
        status = e.get("status") or {}
        st_val  = int((e.get("type") or {}).get("value", 0) or 0)
        raw_res = int(status.get("value", 0) or 0)
        result  = (raw_res + 1) if 0 <= raw_res <= 8 else (15 if raw_res == 15 else 0)
        add(T+(2, d_idx, si), *_integer(_SATA_ST_TYPE.get(st_val, 0)))
        add(T+(3, d_idx, si), *_integer(result))
        add(T+(4, d_idx, si), *_truthvalue(bool(status.get("passed", False))))
        add(T+(5, d_idx, si), *_gauge(int(status.get("remaining_percent", 0) or 0)))
        add(T+(6, d_idx, si), *_counter64(int(e.get("lifetime_hours", 0) or 0)))
        add(T+(7, d_idx, si), *_counter64(int(e.get("lba_first_error", 0) or 0) & 0xFFFFFFFFFFFFFFFF))
    return len(entries)


# --------------------------------------------------------------------------
# SATA ERC table  (.4.1.21.1)
# --------------------------------------------------------------------------

def _add_sata_erc(add, dev: dict, d_idx: int) -> int:
    T   = (4, 1, 21, 1)
    erc = dev["raw"].get("ata_sct_erc") or {}
    count = 0
    for eid, key in ((1, "read"), (2, "write")):
        e = erc.get(key)
        if e is None:
            continue
        add(T+(2, d_idx, eid), *_truthvalue(bool(e.get("enabled", False))))
        add(T+(3, d_idx, eid), *_gauge(int(e.get("deciseconds", 0) or 0)))
        count += 1
    return count


# --------------------------------------------------------------------------
# SATA PHY event counter table  (.4.1.24.1)
# --------------------------------------------------------------------------

def _add_sata_phyevent(add, dev: dict, d_idx: int) -> int:
    T       = (4, 1, 24, 1)
    entries = (dev["raw"].get("sata_phy_event_counters") or {}).get("table") or []
    for e in entries:
        eid = int(e.get("id", 0) or 0)
        if eid == 0:
            continue
        add(T+(2, d_idx, eid), *_string(str(e.get("name") or "")))
        add(T+(3, d_idx, eid), *_gauge(int(e.get("size", 0) or 0)))
        add(T+(4, d_idx, eid), *_counter64(int(e.get("value", 0) or 0)))
        add(T+(5, d_idx, eid), *_truthvalue(bool(e.get("overflow", False))))
    return len(entries)


# --------------------------------------------------------------------------
# SATA selective self-test table (.4.1.27.1) and metadata scalars (.4.1.28-31)
# --------------------------------------------------------------------------

def _add_sata_selective(add, dev: dict, d_idx: int,
                        first_dev: bool = False) -> int:
    T    = (4, 1, 27, 1)
    sel  = dev["raw"].get("ata_smart_selective_self_test_log") or {}
    rows = sel.get("table") or []
    for slot_0, e in enumerate(rows[:5]):
        slot = slot_0 + 1
        add(T+(2, d_idx, slot), *_counter64(int(e.get("lba_min", 0) or 0) & 0xFFFFFFFFFFFFFFFF))
        add(T+(3, d_idx, slot), *_counter64(int(e.get("lba_max", 0) or 0) & 0xFFFFFFFFFFFFFFFF))
        add(T+(4, d_idx, slot), *_gauge(int((e.get("status") or {}).get("value", 0) or 0)))
    if first_dev:
        flags = sel.get("flags") or {}
        add((4, 1, 28, 0), *_gauge(int(sel.get("revision", 0) or 0)))
        add((4, 1, 29, 0), *_gauge(int(flags.get("value", 0) or 0)))
        add((4, 1, 30, 0), *_truthvalue(bool(flags.get("remainder_scan_enabled", False))))
        add((4, 1, 31, 0), *_gauge(int(sel.get("power_up_scan_resume_minutes", 0) or 0)))
    return len(rows[:5])


# --------------------------------------------------------------------------
# SATA log directory table  (.4.1.34.1) and version scalars (.4.1.35-37)
# --------------------------------------------------------------------------

def _add_sata_logdir(add, dev: dict, d_idx: int,
                     first_dev: bool = False) -> int:
    T       = (4, 1, 34, 1)
    logdir  = dev["raw"].get("ata_log_directory") or {}
    entries = logdir.get("table") or []
    for e in entries:
        addr = int(e.get("address", 0) or 0)
        add(T+(2, d_idx, addr), *_string(str(e.get("name") or "")))
        add(T+(3, d_idx, addr), *_truthvalue(bool(e.get("read", False))))
        add(T+(4, d_idx, addr), *_truthvalue(bool(e.get("write", False))))
        add(T+(5, d_idx, addr), *_gauge(int(e.get("gp_sectors", 0) or 0)))
        add(T+(6, d_idx, addr), *_gauge(int(e.get("smart_sectors", 0) or 0)))
    if first_dev:
        add((4, 1, 35, 0), *_gauge(int(logdir.get("gp_dir_version", 0) or 0)))
        add((4, 1, 36, 0), *_gauge(int(logdir.get("smart_dir_version", 0) or 0)))
        add((4, 1, 37, 0), *_truthvalue(bool(logdir.get("smart_dir_multi_sector", False))))
    return len(entries)


# --------------------------------------------------------------------------
# SATA device statistics table  (.4.1.40.1)
# --------------------------------------------------------------------------

def _farm_strip_prefix(parent: str, child: str) -> str:
    """Strip longest common _-word prefix of child that matches parent (C++ logic)."""
    sep = 0
    for i in range(min(len(parent), len(child))):
        if parent[i] != child[i]:
            break
        if child[i] == '_':
            sep = i + 1
    return child[sep:] if sep else child


_FARM_PAGES = [
    ("page_0_log_header",             100, "FARM Log Header"),
    ("page_1_drive_information",      101, "FARM Drive Information"),
    ("page_2_workload_statistics",    102, "FARM Workload Statistics"),
    ("page_3_error_statistics",       103, "FARM Error Statistics"),
    ("page_4_environment_statistics", 104, "FARM Environment Statistics"),
    ("page_5_reliability_statistics", 105, "FARM Reliability Statistics"),
]


def _add_sata_farm(add, raw: dict, d_idx: int) -> int:
    T    = (4, 1, 40, 1)
    farm = raw.get("seagate_farm_log") or {}
    if not farm.get("supported"):
        return 0
    count = 0
    for pg_key, pg_num, pg_name in _FARM_PAGES:
        page_obj = farm.get(pg_key)
        if not isinstance(page_obj, dict):
            continue
        offset = 1
        for key, val in page_obj.items():
            if isinstance(val, (int, float)):
                add(T+(3, d_idx, pg_num, offset), *_string(pg_name))
                add(T+(4, d_idx, pg_num, offset), *_string(key))
                add(T+(5, d_idx, pg_num, offset), *_counter64(int(val)))
                add(T+(6, d_idx, pg_num, offset), *_bits(0, nbits=8))
                offset += 1
                count  += 1
            elif isinstance(val, dict):
                for child_key, child_val in val.items():
                    if not isinstance(child_val, (int, float)):
                        continue
                    short = _farm_strip_prefix(key, child_key)
                    add(T+(3, d_idx, pg_num, offset), *_string(pg_name))
                    add(T+(4, d_idx, pg_num, offset), *_string(f"{key}.{short}"))
                    add(T+(5, d_idx, pg_num, offset), *_counter64(int(child_val)))
                    add(T+(6, d_idx, pg_num, offset), *_bits(0, nbits=8))
                    offset += 1
                    count  += 1
    return count


def _add_sata_devstat(add, dev: dict, d_idx: int) -> int:
    T     = (4, 1, 40, 1)
    pages = (dev["raw"].get("ata_device_statistics") or {}).get("pages") or []
    count = 0
    for page in pages:
        page_num  = int(page.get("number", 0) or 0)
        page_name = str(page.get("name") or "")
        for entry in (page.get("table") or []):
            offset = int(entry.get("offset", 0) or 0)
            flags  = entry.get("flags") or {}
            raw_v  = int(entry.get("value", 0) or 0)
            # pack flags byte: supported=bit7, valid=bit6, normalized=bit5, dsn=bit4, mcm=bit3, rti=bit2
            fval = int(flags.get("value", 0) or 0)
            add(T+(3, d_idx, page_num, offset), *_string(page_name))
            add(T+(4, d_idx, page_num, offset), *_string(str(entry.get("name") or "")))
            add(T+(5, d_idx, page_num, offset), *_counter64(raw_v))
            add(T+(6, d_idx, page_num, offset), *_bits(fval, nbits=8))
            count += 1
    count += _add_sata_farm(add, dev["raw"], d_idx)
    return count


# --------------------------------------------------------------------------
# SATA pending defects table  (.4.1.43.1)
# --------------------------------------------------------------------------

def _add_sata_pending_defects(add, dev: dict, d_idx: int) -> int:
    T       = (4, 1, 43, 1)
    entries = (dev["raw"].get("ata_pending_defects_log") or {}).get("table") or []
    for i, e in enumerate(entries):
        pi = i + 1
        add(T+(2, d_idx, pi), *_counter64(int(e.get("lba", 0) or 0) & 0xFFFFFFFFFFFFFFFF))
    return len(entries)


# --------------------------------------------------------------------------
# Sensor table  (.6.1.3.1)
# --------------------------------------------------------------------------

def _extract_sensors(dev: dict) -> List[dict]:
    raw   = dev["raw"]
    proto = dev["protocol"]
    poll_time = dev.get("poll_time") or datetime.now(timezone.utc)
    sensors: List[dict] = []

    def sensor(idx, stype, name, source, scale, precision, value, status,
               units_display, hi_crit=None, hi_warn=None, lo_warn=None, lo_crit=None):
        sensors.append({
            "idx": idx, "type": stype, "name": name, "source": source,
            "scale": scale, "precision": precision, "value": value,
            "status": status, "units_display": units_display,
            "hi_crit": hi_crit, "hi_warn": hi_warn,
            "lo_warn": lo_warn, "lo_crit": lo_crit,
            "timestamp": poll_time,
        })

    temp = raw.get("temperature") or {}
    t_current = temp.get("current")

    if proto == "nvme":
        h = raw.get("nvme_smart_health_information_log") or {}
        h_temp = h.get("temperature")
        if h_temp is not None:
            t_crit = int(temp.get("op_limit") or temp.get("limit_max") or 70)
            sensor(1, 3, "Composite",
                   "nvme_smart_health_information_log.temperature",
                   9, 0, int(h_temp), 1, "Celsius",
                   hi_crit=t_crit, hi_warn=t_crit - 5)
        spare = h.get("available_spare")
        if spare is not None:
            thr = int(h.get("available_spare_threshold") or 10)
            sensor(2, 10, "Available Spare",
                   "nvme_smart_health_information_log.available_spare",
                   9, 0, int(spare), 1, "percent",
                   lo_warn=thr + 10, lo_crit=thr)
        pct_used = h.get("percentage_used")
        if pct_used is not None:
            sensor(3, 10, "Percentage Used",
                   "nvme_smart_health_information_log.percentage_used",
                   9, 0, int(pct_used), 1, "percent")
        for i, t_val in enumerate(h.get("temperature_sensors") or [], start=0):
            if t_val is not None:
                sensor(10 + i, 3, f"Sensor {i + 1}",
                       f"nvme_smart_health_information_log.temperature_sensors[{i}]",
                       9, 0, int(t_val), 1, "Celsius")
    elif t_current is not None:
        t_crit = int(temp.get("op_limit") or temp.get("limit_max") or 70)
        sensor(1, 3, "temperature", "temperature.current",
               9, 0, int(t_current), 1, "C",
               hi_crit=t_crit, hi_warn=t_crit - 5)

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
        add(T+(6,  d_idx, si), *_integer(s["precision"]))
        add(T+(7,  d_idx, si), *_integer(s["value"]))
        add(T+(8,  d_idx, si), *_integer(s["status"]))
        add(T+(9,  d_idx, si), *_string(s["units_display"]))
        add(T+(10, d_idx, si), *_datetimeval(s["timestamp"]))
        add(T+(11, d_idx, si), *_gauge(0))                  # updateRate
        add(T+(12, d_idx, si), *_integer(s["hi_crit"] or 0))
        add(T+(13, d_idx, si), *_integer(s["hi_warn"] or 0))
        add(T+(14, d_idx, si), *_integer(s["lo_warn"] or 0))
        add(T+(15, d_idx, si), *_integer(s["lo_crit"] or 0))
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


def _binary_octetstring(agent: Any, raw: bytes) -> Any:
    """OctetString for binary data that may contain null bytes.

    ctypes.create_string_buffer stores .value as a null-terminated C string, so
    the library computes _data_size = len(value) which stops at the first 0x00.
    Writing via .raw bypasses that and we fix _data_size manually.
    """
    obj = agent.OctetString()
    obj._cvar.raw = raw.ljust(len(obj._cvar.raw), b'\x00')
    obj._data_size = len(raw)
    return obj


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
        return _binary_octetstring(agent, raw)
    if snmp_type == "bits":
        return _binary_octetstring(agent, value if isinstance(value, bytes) else b"")
    raise ValueError(f"unsupported SNMP type {snmp_type!r}")


def _make_scalar(agent: Any, oidstr: str, snmp_type: str) -> Any:
    if snmp_type == "counter64":
        return agent.Counter64(oidstr=oidstr, writable=False)
    if snmp_type == "gauge":
        return agent.Unsigned32(oidstr=oidstr, writable=False)
    if snmp_type == "integer":
        return agent.Integer32(oidstr=oidstr, writable=False)
    if snmp_type in ("string", "datetimeval", "bits"):
        return agent.OctetString(oidstr=oidstr, writable=False)
    raise ValueError(f"unsupported scalar type {snmp_type!r}")


def _scalar_definitions() -> Dict[Oid, str]:
    return {
        # Common scalars
        _full((2, 1, 1, 0)): "gauge",    # deviceTableRowCount
        _full((2, 1, 2, 0)): "datetimeval", # deviceTableLastChange
        _full((2, 1, 4, 0)): "gauge",    # deviceCountNvme
        _full((2, 1, 5, 0)): "gauge",    # deviceCountAta
        _full((2, 1, 6, 0)): "gauge",    # deviceCountSas
        _full((2, 1, 7, 0)): "gauge",    # pollFailureThreshold
        # NVMe scalars
        _full((3, 1, 1, 0)):  "gauge",       # nvmeControllerTableRowCount
        _full((3, 1, 2, 0)):  "datetimeval", # nvmeControllerTableLastChange
        _full((3, 1, 4, 0)):  "gauge",       # nvmeNamespaceTableRowCount
        _full((3, 1, 5, 0)):  "datetimeval", # nvmeNamespaceTableLastChange
        _full((3, 1, 7, 0)):  "gauge",       # nvmePowerStateTableRowCount
        _full((3, 1, 8, 0)):  "datetimeval", # nvmePowerStateTableLastChange
        _full((3, 1, 10, 0)): "gauge",       # nvmeLbaFormatTableRowCount
        _full((3, 1, 11, 0)): "datetimeval", # nvmeLbaFormatTableLastChange
        _full((3, 1, 13, 0)): "gauge",       # nvmeHealthTableRowCount
        _full((3, 1, 14, 0)): "datetimeval", # nvmeHealthTableLastChange
        _full((3, 1, 16, 0)): "gauge",       # nvmeSelfTestTableRowCount
        _full((3, 1, 17, 0)): "datetimeval", # nvmeSelfTestTableLastChange
        _full((3, 1, 19, 0)): "gauge",       # nvmeErrorLogTableRowCount
        _full((3, 1, 20, 0)): "datetimeval", # nvmeErrorLogTableLastChange
        _full((3, 1, 22, 0)): "gauge",       # nvmeCapabilityTableRowCount
        _full((3, 1, 23, 0)): "datetimeval", # nvmeCapabilityTableLastChange
        # SATA scalars
        _full((4, 1, 1, 0)):  "gauge",        # sataInfoTableRowCount
        _full((4, 1, 4, 0)):  "gauge",        # sataHealthTableRowCount
        _full((4, 1, 5, 0)):  "datetimeval",  # sataHealthTableLastChange
        _full((4, 1, 7, 0)):  "gauge",        # sataAttrTableRowCount
        _full((4, 1, 8, 0)):  "datetimeval",  # sataAttrTableLastChange
        _full((4, 1, 10, 0)): "gauge",        # sataErrorLogTableRowCount
        _full((4, 1, 11, 0)): "datetimeval",  # sataErrorLogTableLastChange
        _full((4, 1, 13, 0)): "gauge",        # sataErrorCmdTableRowCount
        _full((4, 1, 14, 0)): "datetimeval",  # sataErrorCmdTableLastChange
        _full((4, 1, 16, 0)): "gauge",        # sataSelfTestTableRowCount
        _full((4, 1, 17, 0)): "datetimeval",  # sataSelfTestTableLastChange
        _full((4, 1, 19, 0)): "gauge",        # sataErcTableRowCount
        _full((4, 1, 20, 0)): "datetimeval",  # sataErcTableLastChange
        _full((4, 1, 22, 0)): "gauge",        # sataPhyEventTableRowCount
        _full((4, 1, 23, 0)): "datetimeval",  # sataPhyEventTableLastChange
        _full((4, 1, 25, 0)): "gauge",        # sataSelectiveTestTableRowCount
        _full((4, 1, 26, 0)): "datetimeval",  # sataSelectiveTestTableLastChange
        _full((4, 1, 28, 0)): "gauge",        # sataSelectiveLogRevision
        _full((4, 1, 29, 0)): "gauge",        # sataSelectiveFlagsValue
        _full((4, 1, 30, 0)): "integer",      # sataSelectiveRemainderScanEnabled (TruthValue)
        _full((4, 1, 31, 0)): "gauge",        # sataSelectivePowerUpResumeMinutes
        _full((4, 1, 32, 0)): "gauge",        # sataLogDirTableRowCount
        _full((4, 1, 33, 0)): "datetimeval",  # sataLogDirTableLastChange
        _full((4, 1, 35, 0)): "gauge",        # sataLogDirGpVersion
        _full((4, 1, 36, 0)): "gauge",        # sataLogDirSmartVersion
        _full((4, 1, 37, 0)): "integer",      # sataLogDirSmartMultiSector (TruthValue)
        _full((4, 1, 38, 0)): "gauge",        # sataDevStatTableRowCount
        _full((4, 1, 39, 0)): "datetimeval",  # sataDevStatTableLastChange
        _full((4, 1, 41, 0)): "gauge",        # sataPendingDefectsTableRowCount
        _full((4, 1, 42, 0)): "datetimeval",  # sataPendingDefectsTableLastChange
        # SAS scalars
        _full((5, 1, 4, 0)): "gauge",        # sasHealthTableRowCount
        _full((5, 1, 5, 0)): "datetimeval",  # sasHealthTableLastChange
        _full((5, 1, 7, 0)): "gauge",        # sasErrorCounterTableRowCount
        _full((5, 1, 8, 0)): "datetimeval",  # sasErrorCounterTableLastChange
        # Sensor scalars
        _full((6, 1, 1, 0)): "gauge",        # sensorTableRowCount
        _full((6, 1, 2, 0)): "datetimeval",  # sensorTableLastChange
    }


TABLE_DEFINITIONS: Dict[str, dict] = {
    # smartSATAChanges subtree  (.4.1.2)
    "sata_change_meta": {
        "oid_suffix": (4, 1, 2, 1),
        "entry_prefix": _full((4, 1, 2, 1, 1)),
        "indexes": 1,
        "columns": {2: "string", 3: "gauge", 4: "datetimeval"},
    },
    "sata_change_by_device": {
        "oid_suffix": (4, 1, 2, 2),
        "entry_prefix": _full((4, 1, 2, 2, 1)),
        "indexes": 2,
        "columns": {2: "gauge", 3: "datetimeval"},
    },
    "sata_change_by_subidx": {
        "oid_suffix": (4, 1, 2, 3),
        "entry_prefix": _full((4, 1, 2, 3, 1)),
        "indexes": 3,
        "columns": {4: "datetimeval"},
    },
    "sata_info": {
        "oid_suffix": (4, 1, 3),
        "entry_prefix": _full((4, 1, 3, 1)),
        "indexes": 1,
        "columns": {
            1: "integer", 2: "integer", 3: "gauge", 4: "integer",
            5: "gauge", 6: "gauge", 7: "counter64",
            8: "integer", 9: "integer", 10: "integer", 11: "integer",
            12: "counter64", 13: "gauge", 14: "gauge",
            15: "gauge", 16: "gauge",
            17: "integer", 18: "integer", 19: "integer", 20: "integer",
            21: "gauge", 22: "integer", 23: "integer",
            24: "gauge", 25: "gauge", 26: "gauge", 27: "gauge", 28: "gauge",
            29: "integer", 30: "integer", 31: "integer", 32: "integer", 33: "integer",
            40: "integer", 41: "integer", 42: "integer",
            50: "gauge", 51: "gauge", 52: "gauge", 53: "gauge", 54: "gauge", 55: "integer",
            60: "integer", 61: "integer", 62: "integer",
            63: "integer", 64: "integer", 65: "integer", 66: "integer",
        },
    },
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
    "nvme_controller": {
        "oid_suffix": (3, 1, 3),
        "entry_prefix": _full((3, 1, 3, 1)),
        "indexes": 2,
        "columns": {
            1: "gauge", 2: "gauge", 3: "counter64", 4: "counter64",
            5: "gauge", 6: "string", 7: "gauge", 8: "gauge",
            12: "gauge", 13: "gauge", 14: "string", 15: "string",
        },
    },
    "nvme_namespace": {
        "oid_suffix": (3, 1, 6),
        "entry_prefix": _full((3, 1, 6, 1)),
        "indexes": 2,
        "columns": {
            1: "gauge",
            2: "counter64", 3: "counter64", 4: "counter64",
            5: "gauge", 6: "string", 7: "string",
            8: "counter64", 9: "counter64", 10: "counter64",
        },
    },
    "nvme_power_state": {
        "oid_suffix": (3, 1, 9),
        "entry_prefix": _full((3, 1, 9, 1)),
        "indexes": 2,
        "columns": {
            2: "integer", 3: "gauge", 6: "gauge", 7: "gauge",
            8: "gauge", 9: "gauge", 10: "gauge", 11: "gauge",
        },
    },
    "nvme_lba_format": {
        "oid_suffix": (3, 1, 12),
        "entry_prefix": _full((3, 1, 12, 1)),
        "indexes": 3,
        "columns": {
            2: "integer", 3: "gauge", 4: "gauge", 5: "gauge",
        },
    },
    "nvme_health": {
        "oid_suffix": (3, 1, 15),
        "entry_prefix": _full((3, 1, 15, 1)),
        "indexes": 2,
        "columns": {
            1: "integer", 2: "bits",
            7: "counter64", 8: "counter64", 9: "counter64", 10: "counter64",
            11: "counter64", 12: "counter64", 13: "counter64", 14: "counter64",
            15: "counter64", 16: "counter64", 17: "counter64", 18: "counter64",
            19: "counter64", 20: "counter64",
            22: "gauge", 23: "string",
        },
    },
    "nvme_selftest": {
        "oid_suffix": (3, 1, 18),
        "entry_prefix": _full((3, 1, 18, 1)),
        "indexes": 2,
        "columns": {
            2: "gauge", 3: "integer", 4: "integer", 5: "string",
            6: "counter64", 7: "counter64", 8: "gauge", 9: "gauge",
            10: "gauge", 11: "gauge",
        },
    },
    "nvme_errlog": {
        "oid_suffix": (3, 1, 21),
        "entry_prefix": _full((3, 1, 21, 1)),
        "indexes": 2,
        "columns": {
            2: "counter64", 3: "gauge", 4: "gauge", 5: "gauge",
            6: "gauge", 7: "counter64", 8: "gauge", 9: "gauge",
            10: "gauge", 11: "gauge", 12: "integer", 13: "string",
            14: "integer", 15: "datetimeval",
        },
    },
    "nvme_capability": {
        "oid_suffix": (3, 1, 24),
        "entry_prefix": _full((3, 1, 24, 1)),
        "indexes": 2,
        "columns": {
            1: "gauge", 2: "gauge", 3: "integer",
            4: "gauge", 5: "gauge", 6: "gauge",
            7: "string", 8: "string", 9: "string",
        },
    },
    "sata_health": {
        "oid_suffix": (4, 1, 6),
        "entry_prefix": _full((4, 1, 6, 1)),
        "indexes": 1,
        "columns": {
            1: "integer", 2: "integer", 3: "integer",
            4: "counter64", 5: "counter64", 6: "gauge",
            7: "gauge", 8: "gauge", 9: "gauge", 10: "gauge",
            11: "gauge", 12: "gauge", 13: "gauge",
            14: "integer", 15: "integer", 16: "integer", 17: "integer",
            18: "gauge", 19: "gauge", 20: "integer", 21: "gauge",
            22: "datetimeval", 23: "counter64",
        },
    },
    "sata_attr": {
        "oid_suffix": (4, 1, 9),
        "entry_prefix": _full((4, 1, 9, 1)),
        "indexes": 2,
        "columns": {
            2: "string", 3: "bits", 4: "integer", 5: "integer",
            6: "gauge", 7: "gauge", 8: "gauge", 9: "counter64",
            10: "string", 11: "integer",
        },
    },
    "sata_errorlog": {
        "oid_suffix": (4, 1, 12),
        "entry_prefix": _full((4, 1, 12, 1)),
        "indexes": 2,
        "columns": {
            2: "gauge", 3: "counter64", 4: "string",
            5: "gauge", 6: "gauge", 7: "counter64",
            8: "gauge", 9: "gauge", 10: "gauge", 11: "gauge",
            12: "integer",
        },
    },
    "sata_errorcmd": {
        "oid_suffix": (4, 1, 15),
        "entry_prefix": _full((4, 1, 15, 1)),
        "indexes": 3,
        "columns": {
            2: "gauge", 3: "gauge", 4: "gauge", 5: "gauge",
            6: "gauge", 7: "counter64", 8: "gauge", 9: "gauge",
            10: "string",
        },
    },
    "sata_selftest": {
        "oid_suffix": (4, 1, 18),
        "entry_prefix": _full((4, 1, 18, 1)),
        "indexes": 2,
        "columns": {
            2: "integer", 3: "integer", 4: "integer",
            5: "gauge", 6: "counter64", 7: "counter64",
        },
    },
    "sata_erc": {
        "oid_suffix": (4, 1, 21),
        "entry_prefix": _full((4, 1, 21, 1)),
        "indexes": 2,
        "columns": {2: "integer", 3: "gauge"},
    },
    "sata_phyevent": {
        "oid_suffix": (4, 1, 24),
        "entry_prefix": _full((4, 1, 24, 1)),
        "indexes": 2,
        "columns": {2: "string", 3: "gauge", 4: "counter64", 5: "integer"},
    },
    "sata_selective": {
        "oid_suffix": (4, 1, 27),
        "entry_prefix": _full((4, 1, 27, 1)),
        "indexes": 2,
        "columns": {2: "counter64", 3: "counter64", 4: "gauge"},
    },
    "sata_logdir": {
        "oid_suffix": (4, 1, 34),
        "entry_prefix": _full((4, 1, 34, 1)),
        "indexes": 2,
        "columns": {2: "string", 3: "integer", 4: "integer", 5: "gauge", 6: "gauge"},
    },
    "sata_devstat": {
        "oid_suffix": (4, 1, 40),
        "entry_prefix": _full((4, 1, 40, 1)),
        "indexes": 3,
        "columns": {3: "string", 4: "string", 5: "counter64", 6: "bits"},
    },
    "sata_pending_defects": {
        "oid_suffix": (4, 1, 43),
        "entry_prefix": _full((4, 1, 43, 1)),
        "indexes": 2,
        "columns": {2: "counter64"},
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
            6: "integer", 7: "integer", 8: "integer", 9: "string",
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
            (col, _make_value(agent, snmp_type, "" if snmp_type in ("string", "datetimeval", "bits") else 0))
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
            dtype = defns[oid]
            if dtype == "datetimeval":
                raw = _encode_datetimeval(now)
                scalar._cvar.raw = raw.ljust(len(scalar._cvar.raw), b'\x00')
                scalar._data_size = scalar._watcher.contents.data_size = len(raw)
            elif dtype == "string":
                scalar.update(now.isoformat().encode())
            else:
                scalar.update(0)
            continue
        if snmp_type == "datetimeval":
            raw = _encode_datetimeval(value) if isinstance(value, datetime) else b""
            scalar._cvar.raw = raw.ljust(len(scalar._cvar.raw), b'\x00')
            scalar._data_size = scalar._watcher.contents.data_size = len(raw)
        elif snmp_type == "bits":
            raw = value if isinstance(value, bytes) else b""
            scalar._cvar.raw = raw.ljust(len(scalar._cvar.raw), b'\x00')
            scalar._data_size = scalar._watcher.contents.data_size = len(raw)
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
                vtype, val = rows[indexes].get(col, (snmp_type, "" if snmp_type in ("string", "datetimeval", "bits") else 0))
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
