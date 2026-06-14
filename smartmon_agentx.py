#!/usr/bin/env python3
# (c) 2026, LibreNMS
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Self-contained AgentX subagent for SMARTMON-*-MIB."""

from __future__ import annotations

import argparse
import bisect
import ctypes
import ctypes.util
import getpass
import glob
import json
import logging
import os
import queue
import re
import select
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "0.1.5"
__version__ = VERSION

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

# --------------------------------------------------------------------------
# SNMP constants
# --------------------------------------------------------------------------

BASE_OID  = (1, 3, 6, 1, 4, 1, 65891, 1, 1)
# Default TTL = worker poll interval (see _collector_loop).  30s balances trap /
# data-refresh latency against idle cost; CI overrides to 0 for fast traps.
CACHE_TTL = 30

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

# Known protocol suffixes for smartd JSON state files; compiled once since
# _discover_devices() is now called on the main-loop change-detection path.
_PROTO_SUFFIX = re.compile(r'\.(ata|sat|nvme|scsi|sas)\.json$')

# Seagate FARM supplementary state file suffix (e.g. <serial>.farm.ata.json).
_FARM_SIDECAR_SUFFIX = ".farm.ata.json"


def _discover_devices(state_dir: str, config_devices=None) -> List[str]:
    """Return sorted list of smartd JSON device state file paths in state_dir.

    A Seagate FARM supplementary file (*.farm.ata.json) is matched to its sibling
    main device file (<base>.ata.json); the pairing is recorded in
    _st.farm_sidecars so the FARM log merges into that device (it "follows" the
    main device rather than appearing as a separate item).  An orphan FARM file
    with no matching main file is surfaced as its own standalone device.

    Raises CollectionError when no files are found."""
    try:
        all_files = glob.glob(os.path.join(state_dir, "*.json"))
    except OSError as exc:
        raise CollectionError(EXIT_PERMISSION_DENIED,
                              f"cannot scan {state_dir!r}: {exc}") from exc

    # Split into main device files and Seagate FARM sidecars.  Match each FARM
    # sidecar to <base>.ata.json; merged ones drop out of the device list, the
    # rest stand alone.
    main_files, farm_files = [], []
    for f in all_files:
        if f.endswith(_FARM_SIDECAR_SUFFIX):
            farm_files.append(f)
        elif _PROTO_SUFFIX.search(os.path.basename(f)):
            main_files.append(f)

    main_set = set(main_files)
    sidecars: Dict[str, str] = {}
    orphan_farm: List[str] = []
    for ff in farm_files:
        main_candidate = ff[:-len(_FARM_SIDECAR_SUFFIX)] + ".ata.json"
        if main_candidate in main_set:
            sidecars[main_candidate] = ff
        else:
            orphan_farm.append(ff)
    _st.farm_sidecars = sidecars

    files = main_files + orphan_farm

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
    LOGGER.verbose("discovered %d state files in %r", len(files), state_dir)
    return files


# ==========================================================================
# Part 1b — Native collection (smartctl pulled directly, no state_dir files)
#
# Enabled by `collect: true` / --collect.  A native Python port of
# bin/smartmon-collect: scan drives (once, then on udev hotplug — see
# _udev_monitor_loop), run `smartctl -x -j` per drive, merge the Seagate FARM
# log, and hand the parsed objects straight to the build pipeline.
# When not root, smartctl is wrapped in `sudo -n` so only smartctl needs a
# sudoers grant; a failed pull emits one-shot guidance on how to add it.
# ==========================================================================

# stderr fragments that indicate the smartctl call was blocked by privilege,
# not by a real device error — used to surface actionable sudoers guidance.
_PERM_HINTS = ("a password is required", "sudo:", "permission denied",
               "open device", "must be root", "operation not permitted")


def _smartctl_cmd() -> List[str]:
    """Base smartctl argv: bare when root, wrapped in `sudo -n` otherwise."""
    path = shutil.which("smartctl") or "smartctl"
    if os.geteuid() == 0:
        return [path]
    return ["sudo", "-n", path]


def _run_smartctl(args: List[str], timeout: int = 60) -> "subprocess.CompletedProcess":
    """Run smartctl with the configured base argv.

    Never raises: a non-zero exit is returned as-is, and a missing binary or a
    timeout (hung drive) is surfaced as a synthetic failed result so a single
    stuck device can't take down the whole collect cycle."""
    cmd = _smartctl_cmd() + args
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "smartctl timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def _looks_like_perm_failure(proc: "subprocess.CompletedProcess") -> bool:
    err = (proc.stderr or "").lower()
    return any(h in err for h in _PERM_HINTS)


def _warn_sudoers_once() -> None:
    """Log, at most once per run, how to grant the agent passwordless smartctl."""
    if _st.sudoers_warned:
        return
    _st.sudoers_warned = True
    user = getpass.getuser()
    path = shutil.which("smartctl") or "/usr/sbin/smartctl"
    LOGGER.error(
        "cannot read SMART data as non-root user %r — smartctl needs privilege. "
        "Grant passwordless access with:\n"
        "    echo '%s ALL=(root) NOPASSWD: %s' | sudo tee /etc/sudoers.d/smartmon-agentx",
        user, user, path)


def _drive_suffix(dtype: str, dev: str) -> str:
    """Map a smartctl device type / node to a protocol suffix (ata/nvme/...)."""
    if dtype.startswith("nvme"):
        return "nvme"
    if dtype == "sat":
        return "sat"
    if dtype in ("scsi", "sas"):
        return "scsi"
    if dtype == "ata":
        return "ata"
    # auto / unknown: derive from the device node name
    return "nvme" if "/nvme" in dev else "ata"


def _byid_name(dev: str) -> str:
    """Return a stable /dev/disk/by-id name for `dev`, else an encoded node path.

    Mirrors bin/smartmon-collect: prefer nvme-/ata-/scsi- aliases over
    eui./wwn./dm- ones, skip partitions, and keep the shortest among ties."""
    try:
        real = os.path.realpath(dev)
    except OSError:
        real = dev
    # NVMe controller nodes (/dev/nvmeN) — by-id symlinks target /dev/nvmeNn1.
    real_alt = ""
    m = re.match(r"/dev/nvme(\d+)$", real)
    if m:
        real_alt = f"/dev/nvme{m.group(1)}n1"

    byid = "/dev/disk/by-id"
    chosen = ""
    if os.path.isdir(byid):
        for base in os.listdir(byid):
            link = os.path.join(byid, base)
            if not os.path.islink(link):
                continue
            try:
                target = os.path.realpath(link)
            except OSError:
                continue
            if target not in (real, real_alt):
                continue
            if "-part" in base:
                continue
            preferred = base.startswith(("nvme-", "ata-", "scsi-"))
            if not chosen:
                chosen = base
            elif preferred and not chosen.startswith(("nvme-", "ata-", "scsi-")):
                chosen = base
            elif preferred and len(base) < len(chosen):
                chosen = base
    if chosen:
        return chosen
    return dev.lstrip("/").replace("/", "_")


def _discover_drives() -> List[dict]:
    """Scan for drives via smartctl; return one spec dict per drive.

    Spec: {dev, dtype, dev_args, suffix, key}.  `key` is the synthesized stable
    identity used as dev["path"] downstream (removal / consec_fail tracking)."""
    proc = _run_smartctl(["--scan-open"])
    out = proc.stdout or ""
    if proc.returncode != 0 and not out.strip():
        proc = _run_smartctl(["--scan"])
        out = proc.stdout or ""
    if not out.strip():
        if _looks_like_perm_failure(proc):
            _warn_sudoers_once()
        return []

    specs: List[dict] = []
    for line in out.splitlines():
        # Line format: /dev/DEVICE -d TYPE # comment
        parts = line.split()
        if not parts or not parts[0].startswith("/dev/"):
            continue
        dev = parts[0]
        dflag = parts[1] if len(parts) > 1 else ""
        dtype = parts[2] if len(parts) > 2 else ""
        if dflag == "-d" and dtype:
            dev_args = ["-d", dtype]
        else:
            dtype = "auto"
            dev_args = []
        suffix = _drive_suffix(dtype, dev)
        key = f"collect:{_byid_name(dev)}.{suffix}"
        specs.append({"dev": dev, "dtype": dtype, "dev_args": dev_args,
                      "suffix": suffix, "key": key})
    return specs


def _merge_farm(raw: dict, spec: dict) -> None:
    """For ATA/SAT drives, fetch GP Log 0xa6 when -x signals FARM support but
    omits the page data, and splice it into raw (mirrors bin/smartmon-collect)."""
    if spec["suffix"] not in ("ata", "sat"):
        return
    farm = raw.get("seagate_farm_log")
    if not isinstance(farm, dict) or not farm.get("supported"):
        return
    if "page_4_environment_statistics" in farm:
        return  # already fully present in the -x output
    proc = _run_smartctl(["-l", "farm", "-j"] + spec["dev_args"] + [spec["dev"]])
    try:
        fjson = json.loads(proc.stdout or "")
    except json.JSONDecodeError:
        return
    fl = fjson.get("seagate_farm_log")
    if isinstance(fl, dict) and "page_4_environment_statistics" in fl:
        raw["seagate_farm_log"] = fl
        LOGGER.verbose("FARM log merged for %s", spec["dev"])


def _collect_one(spec: dict) -> Optional[Tuple[str, dict]]:
    """Pull one drive: run `smartctl -x -j`, merge FARM, return (key, raw).

    Accepts a non-zero exit when the output is still valid JSON (SMART status
    bits set).  Returns None on real failure; flags perm issues for guidance."""
    _t0 = time.monotonic()
    proc = _run_smartctl(["-x", "-j"] + spec["dev_args"] + [spec["dev"]])
    elapsed = time.monotonic() - _t0
    out = proc.stdout or ""
    if proc.returncode != 0 and "json_format_version" not in out:
        if _looks_like_perm_failure(proc):
            _warn_sudoers_once()
        else:
            LOGGER.warning("smartctl failed for %s (type=%s) — skipped",
                           spec["dev"], spec["dtype"])
        return None
    try:
        raw = json.loads(out)
    except json.JSONDecodeError as exc:
        LOGGER.warning("smartctl output for %s was not valid JSON: %s",
                       spec["dev"], exc)
        return None
    _merge_farm(raw, spec)
    LOGGER.verbose("collected %s (type=%s) in %.3fs", spec["dev"], spec["dtype"], elapsed)
    return spec["key"], raw


def _collect_all() -> List[Tuple[str, dict]]:
    """Pull every known drive.  Sequential today; this loop is the seam for a
    future ThreadPoolExecutor (parallel per-disk pulls).

    Device discovery (`smartctl --scan`) only re-runs on the first cycle or when
    the udev monitor (_rescan_event) signals a block-device hotplug; otherwise
    the cached spec set is reused so steady-state polls just refresh SMART data.

    Raises CollectionError when no drives are found, or when drives exist but
    every pull is blocked (e.g. missing sudoers grant)."""
    if _st.collect_specs is None or _rescan_event.is_set():
        _rescan_event.clear()
        _st.collect_specs = _discover_drives()
        LOGGER.verbose("discovered %d drive(s) via smartctl", len(_st.collect_specs))
    specs = _st.collect_specs
    if not specs:
        # Retry discovery next cycle (a transient/permission scan failure leaves
        # no device to fire a udev event that would otherwise un-stick us).
        _st.collect_specs = None
        raise CollectionError(EXIT_NO_DEVICES, "no drives discovered via smartctl")

    collected: List[Tuple[str, dict]] = []
    for spec in specs:
        res = _collect_one(spec)
        if res is not None:
            collected.append(res)

    if not collected:
        if _st.sudoers_warned:
            raise CollectionError(EXIT_PERMISSION_DENIED,
                                  "smartctl could not access any drive (privilege)")
        raise CollectionError(EXIT_PARTIAL_FAILURE,
                              "smartctl could not collect any drive")
    return collected


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
    except (OSError, json.JSONDecodeError) as exc:
        result["read_error"] = str(exc)
        return result
    farm_path = _st.farm_sidecars.get(path)
    if farm_path:
        _merge_farm_file(raw, farm_path)
    return _parse_device_from_raw(raw, path)


def _merge_farm_file(raw: dict, farm_path: str) -> None:
    """Splice seagate_farm_log from a sibling *.farm.ata.json into the main
    device's raw object so the FARM pages/sensors follow the main device."""
    try:
        with open(farm_path) as fh:
            fjson = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("could not read FARM sidecar %s: %s", farm_path, exc)
        return
    fl = fjson.get("seagate_farm_log")
    if isinstance(fl, dict) and (fl.get("supported")
                                 or any(k.startswith("page_") for k in fl)):
        raw["seagate_farm_log"] = fl
        LOGGER.verbose("FARM log merged from %s", os.path.basename(farm_path))


def _parse_device_from_raw(raw: dict, path: str) -> dict:
    """Derive a device dict from an already-loaded smartctl JSON object.

    Shared by the file reader (_parse_device_json) and collect mode, which feeds
    the live `smartctl -x -j` output here directly without touching disk."""
    result: Dict[str, Any] = {
        "path": path, "name": "", "device_path": "", "protocol": "",
        "device_type": 0, "poll_time": None, "smart_passed": None,
        "model_family": "", "model_name": "", "serial_number": "",
        "firmware_version": "", "wwn": "", "raw": raw, "read_error": None,
    }

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
    LOGGER.verbose("parsed device %s (proto=%s model=%r)",
                   result["name"] or path, proto_str, model_name)
    return result


# ==========================================================================
# Part 2 — SNMP type helpers and FNV-1a index assignment
# ==========================================================================

# Sentinel returned by the numeric helpers when the source value is missing
# (None). _build's add() drops these so the OID never enters the oid_map — for
# the custom-handler sensor table that surfaces as noSuchInstance, the honest
# SNMP representation of "no data" rather than a fabricated 0.
_OMIT = object()

def _truthvalue(b) -> tuple:
    return ("integer", "1" if b else "2")

def _gauge(v) -> tuple:
    return (_OMIT, None) if v is None else ("gauge", str(int(v)))

def _counter64(v) -> tuple:
    return (_OMIT, None) if v is None else ("counter64", str(int(v)))

def _string(v) -> tuple:
    return ("string", "" if v is None else str(v))

def _integer(v) -> tuple:
    return (_OMIT, None) if v is None else ("integer", str(int(v)))

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


def _rows_fingerprint(rows: dict) -> int:
    """Deterministic fingerprint of the per-table {indexes: {col: (typ, val)}}
    structure built in _publish_tables, used to skip republishing unchanged
    tables to net-snmp."""
    parts = []
    for indexes in sorted(rows):
        cells = rows[indexes]
        for col in sorted(cells):
            typ, val = cells[col]
            parts.append(f"{indexes}\x00{col}\x00{typ}\x00{val}")
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
    dev_checksums:  dict   # (table_id, d_idx) -> fingerprint int
    dev_timestamps: dict   # (table_id, d_idx) -> datetime
    sub_checksums:  dict   # (table_id, d_idx, sub1) -> fingerprint int
    sub_timestamps: dict   # (table_id, d_idx, sub1) -> datetime
    state_dir:      str
    config_devices: Optional[list]
    file_mtimes:    dict   # path -> stat signature (size, mtime, ctime); change detection
    published_fp:   dict   # table name -> fingerprint of last content pushed to net-snmp

    def __init__(self):
        self.oid_keys              = []
        self.oid_map               = {}
        self.last_load             = 0.0
        self.ttl                   = CACHE_TTL
        self.checksums             = {}
        self.timestamps            = {}
        # Per-device SATA change tracking for the ByDevice change table:
        #   key (table_id, d_idx) -> fingerprint int / datetime
        self.dev_checksums         = {}
        self.dev_timestamps        = {}
        # Per-subindex SATA change tracking for the BySubindex change table:
        #   key (table_id, d_idx, sub1) -> fingerprint int / datetime
        self.sub_checksums         = {}
        self.sub_timestamps        = {}
        self.state_dir             = ""
        self.config_devices        = None
        self.poll_failure_threshold = 1
        # Collect mode: pull SMART data directly via smartctl instead of reading
        # state_dir JSON files.  sudoers_warned gates the one-shot guidance log.
        self.collect               = False
        self.sudoers_warned        = False
        # DEBUG-AGENTX log level: app DEBUG + net-snmp AgentX PDU tracing.
        self.agentx_debug          = False
        self.log_path              = ""
        # Cached drive specs in collect mode.  None forces a `smartctl --scan`;
        # otherwise the cached set is reused and discovery only re-runs when the
        # udev monitor (or a transient empty scan) requests a rescan.
        self.collect_specs: Optional[list] = None
        self.udev_proc             = None   # running `udevadm monitor` subprocess
        # File mode: main-device path -> sibling *.farm.ata.json path whose
        # seagate_farm_log merges into that device (see _discover_devices).
        self.farm_sidecars: dict   = {}
        # Notification config (mirrors AgentxConfig in the C++ daemon).
        self.test_mode             = False
        self.sensor_hysteresis     = 0
        self.sensor_resend_interval = 0
        # Per-device selftest progress: dev_idx -> {start_ns, last_remaining, polling_min, estimated_completion}
        self.selftest_progress: dict = {}
        self.file_mtimes: dict = {}
        self.published_fp: dict = {}
        # Tables flagged custom_handler are served by a custom net-snmp handler
        # (not table_dataset) so missing cells answer noSuchInstance/noSuchObject
        # instead of a fabricated 0/"".  The main thread refreshes these from each
        # published oid_map snapshot; the handler (also main thread) reads them.
        # custom_vals maps the full OID tuple -> (asn_type, value); custom_oids is
        # the sorted key list used for GETNEXT successor lookup.
        self.custom_vals: dict = {}
        self.custom_oids: list = []
        # Last counts logged at INFO; the "built OID table" / "published N OIDs"
        # lines only emit at INFO when these change (otherwise VERBOSE), so a
        # steady-state collect-mode poll does not repeat them every cycle.
        self.last_built_devices    = -1
        self.last_published_oids   = -1
        # ---- systemd sd_notify STATUS= fields (see _sd_status_text) ----
        # Updated at the end of every _build so the line stays current; surfaced
        # to systemd on READY, on each refresh, and on agentx connect/disconnect.
        self.last_device_count     = 0
        self.last_update_ts: Optional[datetime] = None
        self.last_err_code         = EXIT_SUCCESS
        self.last_err_msg          = ""
        self.agentx_connected      = False
        # ---- Notification baseline state (change detection across refreshes) ----
        # Set True after the first build so device-discovered traps are suppressed
        # for the devices present at startup.
        self.initial_scan_done     = False
        # path -> {"d_idx","name","device_path","dev_type"} for devices last seen,
        # used for poll-failure (path still present) and removal (path gone) traps.
        self.file_identity: dict   = {}
        self.consec_fail: dict     = {}   # path -> consecutive parse-failure count
        self.known_didx: set       = set()  # device indexes seen at least once
        self.device_health: dict   = {}   # d_idx -> overall health enum
        self.failed_selftest: dict = {}   # d_idx -> highest failed self-test entry
        self.attr_failing: dict    = {}   # d_idx -> set(attr_id) below threshold
        self.sas_uncorrected: dict = {}   # (d_idx, direction) -> uncorrected count
        self.sensor_alarm_state: dict = {}      # (d_idx, sensor_idx) -> alarm state
        self.sensor_alarm_last_sent: dict = {}  # (d_idx, sensor_idx) -> monotonic ts


_st = _State()

# Producer/consumer handoff: the worker thread builds a fresh oid_map and puts
# it here; the main thread drains it and runs the (net-snmp-touching) publish.
# Only the worker mutates _st; only the main thread reads queued snapshots.
_publish_q: "queue.Queue[dict]" = queue.Queue()

# Lazy refresh: after the initial load there is NO background refresh timer.
# The main thread sets this event whenever a client (SNMP/AgentX) packet wakes
# check_and_process, and the worker only re-reads state files when asked — and
# even then only past the TTL guard (or when fixture mtimes changed).
_refresh_request = threading.Event()

# Set by the udev monitor thread (collect mode) when a block device is added or
# removed, asking the collector to re-run `smartctl --scan` on its next cycle
# instead of re-discovering every poll.  Coalescing: multiple sets before the
# collector runs collapse into a single rescan.
_rescan_event = threading.Event()

# Set by the worker after every poll cycle so the main thread refreshes the
# systemd STATUS= line.  This is decoupled from _publish_q (which only carries a
# snapshot when the data actually changed): liveness — the "updated" timestamp —
# must advance every poll even when nothing is republished to net-snmp.  Sending
# the datagram stays on the main thread to keep one sd_notify caller.
_status_event = threading.Event()


# ==========================================================================
# Part 3b — SQLite state persistence (Python port of agentxd_state_db.cpp)
#
# Persists table change hashes + LastChange timestamps and the notification
# baselines so they survive a daemon restart: LastChange scalars stay accurate
# and traps don't re-storm on the first build after a restart.  Disabled when no
# state_db path is configured (timestamps still work within a single run).
#
# Threading: the connection is opened + loaded on the main thread *before* the
# worker starts, and thereafter only state_db_save() (called from _build) on the
# worker thread touches it; close() runs after the worker joins.  Access is
# therefore never concurrent, so check_same_thread=False is safe.
#
# Every DB call is wrapped so a persistence error can never break data serving.
# ==========================================================================

_db: "Optional[sqlite3.Connection]" = None
_db_path: str = ""

_STATE_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS table_state (
    table_name  TEXT PRIMARY KEY,
    hash        INTEGER NOT NULL,
    last_change INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sata_by_dev_state (
    dev_id      INTEGER NOT NULL,
    table_id    INTEGER NOT NULL,
    hash        INTEGER NOT NULL,
    last_change INTEGER NOT NULL,
    PRIMARY KEY (dev_id, table_id)
);
CREATE TABLE IF NOT EXISTS sata_sub_state (
    dev_id      INTEGER NOT NULL,
    table_id    INTEGER NOT NULL,
    sub1        INTEGER NOT NULL,
    hash        INTEGER NOT NULL,
    last_change INTEGER NOT NULL,
    PRIMARY KEY (dev_id, table_id, sub1)
);
CREATE TABLE IF NOT EXISTS sensor_alarm_state (
    dev_id      INTEGER NOT NULL,
    sensor_idx  INTEGER NOT NULL,
    alarm_state INTEGER NOT NULL,
    last_sent   INTEGER NOT NULL,
    PRIMARY KEY (dev_id, sensor_idx)
);
CREATE TABLE IF NOT EXISTS sata_attr_alarm (
    dev_id  INTEGER NOT NULL,
    attr_id INTEGER NOT NULL,
    PRIMARY KEY (dev_id, attr_id)
);
CREATE TABLE IF NOT EXISTS sas_uncorrected_baseline (
    dev_id      INTEGER NOT NULL,
    direction   INTEGER NOT NULL,
    uncorrected INTEGER NOT NULL,
    PRIMARY KEY (dev_id, direction)
);
CREATE TABLE IF NOT EXISTS sata_selftest_progress (
    dev_id               INTEGER PRIMARY KEY,
    start_ns             INTEGER NOT NULL,
    last_remaining       INTEGER NOT NULL,
    polling_min          INTEGER NOT NULL,
    estimated_completion INTEGER NOT NULL
);
"""


def _epoch(dt: datetime) -> int:
    """datetime -> integer epoch seconds (for persisting a LastChange ts)."""
    return int(dt.timestamp())


def _from_epoch(ts: int) -> datetime:
    """Integer epoch seconds -> UTC-aware datetime."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def state_db_open(path: str) -> bool:
    """Open (or create) the state DB.  Empty path disables persistence.

    Returns False on failure — non-fatal; timestamps still work within a run."""
    global _db, _db_path
    if not path:
        LOGGER.verbose("state_db: disabled (no state_db configured)")
        return True
    existed = os.path.exists(path)
    try:
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        _db = sqlite3.connect(path, check_same_thread=False)
        _db.executescript(_STATE_DB_SCHEMA)
        _db.commit()
    except (sqlite3.Error, OSError) as exc:
        LOGGER.warning("state_db: cannot open %r: %s", path, exc, exc_info=True)
        if _db is not None:
            _db.close()
        _db = None
        return False
    _db_path = path
    LOGGER.verbose("state_db: %s %r", "opened" if existed else "created", path)
    return True


def state_db_load() -> None:
    """Load persisted state into _st.  Call once after open, before first build."""
    if _db is None:
        return
    try:
        cur = _db.cursor()

        n = 0
        for name, h, ts in cur.execute(
                "SELECT table_name, hash, last_change FROM table_state"):
            _st.checksums[name]  = h
            _st.timestamps[name] = _from_epoch(ts)
            n += 1
        LOGGER.verbose("state_db: loaded %d table timestamp(s)", n)

        for dev, tid, h, ts in cur.execute(
                "SELECT dev_id, table_id, hash, last_change FROM sata_by_dev_state"):
            _st.dev_checksums[(tid, dev)]  = h
            _st.dev_timestamps[(tid, dev)] = _from_epoch(ts)

        for dev, tid, sub1, h, ts in cur.execute(
                "SELECT dev_id, table_id, sub1, hash, last_change FROM sata_sub_state"):
            _st.sub_checksums[(tid, dev, sub1)]  = h
            _st.sub_timestamps[(tid, dev, sub1)] = _from_epoch(ts)

        # sensor last_sent is persisted as wall-clock epoch but compared against
        # time.monotonic() at runtime; rebase it so "elapsed since last sent" is
        # preserved across restart without ever yielding a future monotonic time.
        mono_now, wall_now = time.monotonic(), time.time()
        for dev, sidx, astate, last_wall in cur.execute(
                "SELECT dev_id, sensor_idx, alarm_state, last_sent FROM sensor_alarm_state"):
            key = (dev, sidx)
            _st.sensor_alarm_state[key]     = astate
            _st.sensor_alarm_last_sent[key] = mono_now - max(0.0, wall_now - last_wall)

        for dev, attr in cur.execute("SELECT dev_id, attr_id FROM sata_attr_alarm"):
            _st.attr_failing.setdefault(dev, set()).add(attr)

        for dev, direction, unc in cur.execute(
                "SELECT dev_id, direction, uncorrected FROM sas_uncorrected_baseline"):
            _st.sas_uncorrected[(dev, direction)] = unc

        for dev, start_ns, last_rem, pmin, est in cur.execute(
                "SELECT dev_id, start_ns, last_remaining, polling_min,"
                " estimated_completion FROM sata_selftest_progress"):
            _st.selftest_progress[dev] = {
                "start_ns": start_ns, "last_remaining": last_rem,
                "polling_min": pmin, "estimated_completion": est,
            }
        cur.close()
    except sqlite3.Error as exc:
        LOGGER.warning("state_db: load failed: %s", exc, exc_info=True)


def state_db_save() -> None:
    """Snapshot the full in-memory baseline to the DB in one transaction.

    Mirrors the per-key writes of the C++ daemon but, given the Python agent
    rebuilds the whole table set each cycle, a clear+rewrite is simpler and drops
    removed-device rows for free.  Called at the end of _build (worker thread)."""
    if _db is None:
        return
    try:
        wall_now, mono_now = time.time(), time.monotonic()
        sensor_rows = [
            (dev, sidx, _st.sensor_alarm_state[(dev, sidx)],
             int(wall_now - (mono_now - _st.sensor_alarm_last_sent.get((dev, sidx), mono_now))))
            for (dev, sidx) in _st.sensor_alarm_state
        ]
        with _db:   # transaction: commits on success, rolls back on error
            _db.execute("DELETE FROM table_state")
            _db.executemany(
                "INSERT INTO table_state (table_name, hash, last_change) VALUES (?,?,?)",
                [(name, h, _epoch(_st.timestamps.get(name, _from_epoch(0))))
                 for name, h in _st.checksums.items()])

            _db.execute("DELETE FROM sata_by_dev_state")
            _db.executemany(
                "INSERT INTO sata_by_dev_state (dev_id, table_id, hash, last_change)"
                " VALUES (?,?,?,?)",
                [(dev, tid, h, _epoch(_st.dev_timestamps.get((tid, dev), _from_epoch(0))))
                 for (tid, dev), h in _st.dev_checksums.items()])

            _db.execute("DELETE FROM sata_sub_state")
            _db.executemany(
                "INSERT INTO sata_sub_state (dev_id, table_id, sub1, hash, last_change)"
                " VALUES (?,?,?,?,?)",
                [(dev, tid, sub1, h,
                  _epoch(_st.sub_timestamps.get((tid, dev, sub1), _from_epoch(0))))
                 for (tid, dev, sub1), h in _st.sub_checksums.items()])

            _db.execute("DELETE FROM sensor_alarm_state")
            _db.executemany(
                "INSERT INTO sensor_alarm_state (dev_id, sensor_idx, alarm_state, last_sent)"
                " VALUES (?,?,?,?)", sensor_rows)

            _db.execute("DELETE FROM sata_attr_alarm")
            _db.executemany(
                "INSERT INTO sata_attr_alarm (dev_id, attr_id) VALUES (?,?)",
                [(dev, attr) for dev, attrs in _st.attr_failing.items() for attr in attrs])

            _db.execute("DELETE FROM sas_uncorrected_baseline")
            _db.executemany(
                "INSERT INTO sas_uncorrected_baseline (dev_id, direction, uncorrected)"
                " VALUES (?,?,?)",
                [(dev, direction, unc)
                 for (dev, direction), unc in _st.sas_uncorrected.items()])

            _db.execute("DELETE FROM sata_selftest_progress")
            _db.executemany(
                "INSERT INTO sata_selftest_progress"
                " (dev_id, start_ns, last_remaining, polling_min, estimated_completion)"
                " VALUES (?,?,?,?,?)",
                [(dev, p["start_ns"], p["last_remaining"], p["polling_min"],
                  int(p["estimated_completion"]))
                 for dev, p in _st.selftest_progress.items()])
    except sqlite3.Error as exc:
        LOGGER.warning("state_db: save failed: %s", exc, exc_info=True)


def state_db_close() -> None:
    global _db, _db_path
    if _db is not None:
        LOGGER.info("state_db: closing %r", _db_path)
        try:
            _db.close()
        except sqlite3.Error:
            pass
        _db = None
        _db_path = ""

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
    "sata_info":            _full((4, 1, 3, 1)),
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
    1:  "sata_info",
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


_SATA_BYSUBINDEX_TIDS = (5, 11)   # tableIds tracked by the BySubindex change table


def _sata_track_changes(entries: list,
                        sata_dev_counts: Dict[int, Dict[int, int]],
                        sata_dev_subidx: set, ts: datetime):
    """Compute per-device and per-subindex SATA change timestamps.

    The ByDevice/BySubindex change tables must advance LastChange only for the
    device (and subindex) whose rows actually changed — a global per-table
    timestamp would advance every device's row whenever any one device changed.
    Returns (dev_ts, sub_ts):
        dev_ts[(table_id, d_idx)]        -> datetime
        sub_ts[(table_id, d_idx, sub1)]  -> datetime
    """
    # Seed buckets for every (table_id, d_idx) so a table with 0 rows for a
    # device still gets a stable (constant-empty) fingerprint rather than
    # falling back to the ever-advancing cycle timestamp.
    dev_parts: Dict[tuple, list] = {}
    for d_idx in sata_dev_counts:
        for tid in range(1, 13):
            dev_parts[(tid, d_idx)] = []
    sub_parts: Dict[tuple, list] = {}
    for d_idx, tid, sub1 in sata_dev_subidx:
        sub_parts[(tid, d_idx, sub1)] = []

    tbl = [(tid,
            _TABLE_PREFIXES[_SATA_CHANGE_TABLE_LC_KEYS[tid]],
            len(_TABLE_PREFIXES[_SATA_CHANGE_TABLE_LC_KEYS[tid]]))
           for tid in range(1, 13)]
    for oid, typ, val in entries:
        for tid, prefix, plen in tbl:
            if oid[:plen] == prefix:
                d_idx = oid[plen + 1]
                cell  = f"{oid[plen:]}\x00{typ}\x00{val}"
                dev_parts.setdefault((tid, d_idx), []).append(cell)
                if tid in _SATA_BYSUBINDEX_TIDS and len(oid) > plen + 2:
                    sub1 = oid[plen + 2]
                    sub_parts.setdefault((tid, d_idx, sub1), []).append(cell)
                break

    dev_ts: Dict[tuple, datetime] = {}
    for key, parts in dev_parts.items():
        fp = _fnv1a_32("\x01".join(sorted(parts)).encode("utf-8", errors="replace"))
        if fp != _st.dev_checksums.get(key):
            _st.dev_checksums[key]  = fp
            _st.dev_timestamps[key] = ts
        dev_ts[key] = _st.dev_timestamps.get(key, ts)

    sub_ts: Dict[tuple, datetime] = {}
    for key, parts in sub_parts.items():
        fp = _fnv1a_32("\x01".join(sorted(parts)).encode("utf-8", errors="replace"))
        if fp != _st.sub_checksums.get(key):
            _st.sub_checksums[key]  = fp
            _st.sub_timestamps[key] = ts
        sub_ts[key] = _st.sub_timestamps.get(key, ts)

    return dev_ts, sub_ts


def _add_sata_changes(add, entries: list,
                      sata_dev_counts: Dict[int, Dict[int, int]],
                      sata_dev_subidx: set, ts: datetime,
                      total_counts: Dict[int, int]) -> None:
    """Populate the smartSATAChanges subtree (.4.1.2)."""
    dev_ts, sub_ts = _sata_track_changes(entries, sata_dev_counts,
                                         sata_dev_subidx, ts)

    # MetadataTable  (.4.1.2.1.1)  — 12 rows, INDEX { tableId }
    # Aggregate "any device changed this table" => global per-table timestamp.
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
            lc        = dev_ts.get((tid, d_idx), ts)
            add(BDT+(2, d_idx, tid), *_gauge(row_count))
            add(BDT+(3, d_idx, tid), *_datetimeval(lc))

    # BySubindexTable  (.4.1.2.3.1)  — INDEX { deviceIndex, tableId, subindex1 }
    BST = (4, 1, 2, 3, 1)
    for d_idx, tid, sub1 in sorted(sata_dev_subidx):
        lc = sub_ts.get((tid, d_idx, sub1), ts)
        add(BST+(4, d_idx, tid, sub1), *_datetimeval(lc))


def _build(devices: list, ts: datetime,
           error_code: int = EXIT_SUCCESS, error_string: str = "") -> None:
    """Rebuild the OID map from a list of parsed device dicts."""
    entries: List[Tuple] = []

    def add(suffix, typ, val):
        if typ is _OMIT:
            return                      # missing value → omit the OID (null)
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

    devs_with_idx: List[Tuple[int, dict]] = []
    for dev in sorted(devices, key=lambda d: (d["serial_number"], d["model_name"])):
        d_idx = _device_index(dev, used_d_idx)
        used_d_idx.add(d_idx)
        devs_with_idx.append((d_idx, dev))
        _st.file_identity[dev["path"]] = {
            "d_idx":       d_idx,
            "name":        dev["name"],
            "device_path": dev["device_path"],
            "dev_type":    dev["device_type"],
        }

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
            LOGGER.verbose("table %s changed (fp %08x)", tname, fp & 0xFFFFFFFF)
        add(lc_suffix, "datetimeval", _st.timestamps.get(tname, ts))

    # sata_info has no SNMP LastChange scalar but needs a stable fingerprint
    # timestamp for the ByDevice change table (tableId=1).
    fp_si = _table_fingerprint(entries, _TABLE_PREFIXES["sata_info"])
    if fp_si != _st.checksums.get("sata_info"):
        _st.checksums["sata_info"]  = fp_si
        _st.timestamps["sata_info"] = ts
        LOGGER.verbose("table sata_info changed (fp %08x)", fp_si & 0xFFFFFFFF)

    # Build smartSATAChanges subtree after timestamps are updated so
    # MetadataTable lastChange reflects the current cycle's changes.
    total_sata_counts = {
        1: n_ata, 2: n_ata, 3: n_sata_attrs, 4: n_sata_errorlog,
        5: n_sata_errorcmd, 6: n_sata_selftest, 7: n_sata_erc,
        8: n_sata_phyevent, 9: n_sata_selective, 10: n_sata_logdir,
        11: n_sata_devstat, 12: n_sata_pending_def,
    }
    _add_sata_changes(add, entries, sata_dev_counts, sata_dev_subidx, ts, total_sata_counts)

    entries.sort(key=lambda e: e[0])
    _st.oid_keys = [e[0] for e in entries]
    _st.oid_map  = {e[0]: (e[1], e[2]) for e in entries}
    LOGGER.debug("OID table built: %d entries", len(entries))

    # Snapshot for the systemd STATUS= line (set even on error builds).
    _st.last_device_count = n_total
    _st.last_update_ts    = ts
    _st.last_err_code     = error_code
    _st.last_err_msg      = error_string

    # Change detection / trap dispatch (enqueues descriptors onto _notify_q).
    for d_idx, dev in devs_with_idx:
        try:
            _detect_device_notifications(d_idx, dev)
        except Exception as exc:    # never let a trap bug break data serving
            LOGGER.error("notify: detection failed for d_idx=%d: %s", d_idx, exc,
                         exc_info=True)

    # Persist the freshly-updated hashes/timestamps and notification baselines so
    # they survive a restart (no-op when state_db is unconfigured).
    state_db_save()


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
    # Fields used in arithmetic / _bits / change detection keep a 0 default;
    # the directly-emitted counters use None so a field the drive omits drops
    # out of the oid_map and reads as noSuchInstance rather than a fake 0.
    return {
        "critical_warning":        h.get("critical_warning", 0),
        "available_spare":         h.get("available_spare"),
        "available_spare_threshold": h.get("available_spare_threshold"),
        "percentage_used":         h.get("percentage_used"),
        "data_units_read":         h.get("data_units_read", 0),
        "data_units_written":      h.get("data_units_written", 0),
        "host_reads":              h.get("host_reads"),
        "host_writes":             h.get("host_writes"),
        "controller_busy_minutes": h.get("controller_busy_time"),
        "power_cycles":            h.get("power_cycles"),
        "power_on_hours":          h.get("power_on_hours"),
        "unsafe_shutdowns":        h.get("unsafe_shutdowns"),
        "media_errors":            h.get("media_errors"),
        "num_err_log_entries":     h.get("num_err_log_entries"),
        "warning_temp_time":       h.get("warning_temp_time"),
        "critical_comp_time":      h.get("critical_comp_time_minutes"),
    }


def _add_nvme_health(add, dev: dict, d_idx: int) -> None:
    """NVMe health table (.3.1.15.1) — INDEX { smartmonDeviceIndex, healthIdx(=1) }.
    Cols 3-6 are commented out in MIB (moved to SENSOR-MIB)."""
    T  = (3, 1, 15, 1)
    h  = _parse_nvme_health(dev["raw"])
    LOGGER.verbose("parsed nvme health d_idx=%d", d_idx)
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
    # smartctl emits the running operation as nvme_self_test_log.
    # current_self_test_operation {value, string}; "No self-test in progress"
    # (value 0) is a real, reportable state, so keep the descriptive string.
    st_log = dev["raw"].get("nvme_self_test_log") or {}
    cur_op = st_log.get("current_self_test_operation") or {}
    st_val = int(cur_op.get("value", 0))
    st_str = str(cur_op.get("string") or "")
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
    # firmwareResetRequired (frmw "activation without reset"): standard smartctl
    # doesn't decode this, so when the capability object is absent report false
    # (no reset required) rather than defaulting to true.
    add(T+(3, d_idx, ci), *_integer(1 if (fw and not fw.get("activation_without_reset")) else 2))
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
    LOGGER.verbose("parsed sata info d_idx=%d", d_idx)
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
    LOGGER.verbose("parsed sata health d_idx=%d", d_idx)
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
    LOGGER.verbose("parsed sata attrs d_idx=%d (%d rows)", d_idx, len(rows))
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
    LOGGER.verbose("parsed sas health d_idx=%d", d_idx)
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
    LOGGER.verbose("parsed sas error counters d_idx=%d (%d rows)", d_idx, len(rows))
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
        ei  = i + 1
        lba = int(e.get("lba", 0) or 0)
        add(T+(2,  d_idx, ei), *_gauge(int(e.get("error_number", 0) or 0)))
        add(T+(3,  d_idx, ei), *_counter64(int(e.get("lifetime_hours", 0) or 0)))
        add(T+(4,  d_idx, ei), *_string(str(e.get("description") or "")))
        add(T+(5,  d_idx, ei), *_gauge(int(e.get("completion_register_error", 0) or 0)))
        add(T+(6,  d_idx, ei), *_gauge(int(e.get("completion_register_status", 0) or 0)))
        add(T+(7,  d_idx, ei), *_counter64(lba & 0xFFFFFFFFFFFFFFFF))
        add(T+(8,  d_idx, ei), *_gauge(int(e.get("register_command", 0) or 0)))
        add(T+(9,  d_idx, ei), *_gauge(int(e.get("register_count", 0) or 0)))
        add(T+(10, d_idx, ei), *_gauge(int(e.get("register_device", 0) or 0)))
        add(T+(11, d_idx, ei), *_gauge(int(e.get("register_feature", 0) or 0)))
        add(T+(12, d_idx, ei), *_integer(int((e.get("state") or {}).get("value", 0) or 0) & 0xF))
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


def _sata_selftest_table(raw: dict) -> list:
    """smartctl -x reports the extended self-test log; fall back to standard
    (matches the C++ daemon).  Returns the chosen table (possibly empty)."""
    log = raw.get("ata_smart_self_test_log") or {}
    ext = (log.get("extended") or {}).get("table")
    if isinstance(ext, list):
        return ext
    std = (log.get("standard") or {}).get("table")
    return std if isinstance(std, list) else []


def _add_sata_selftest(add, dev: dict, d_idx: int) -> int:
    T       = (4, 1, 18, 1)
    entries = _sata_selftest_table(dev["raw"])
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
        add(T+(7, d_idx, si), *_counter64(int(e.get("lba_of_first_error", 0) or 0) & 0xFFFFFFFFFFFFFFFF))
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
            fval = int(flags.get("value", 0) or 0)
            add(T+(3, d_idx, page_num, offset), *_string(page_name))
            add(T+(4, d_idx, page_num, offset), *_string(str(entry.get("name") or "")))
            add(T+(5, d_idx, page_num, offset), *_counter64(raw_v))
            add(T+(6, d_idx, page_num, offset), "bits", bytes([fval & 0xFF]))
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
        # Composite/per-sensor temperature thresholds come from the dedicated
        # smartctl field; NVMe provides no per-sensor thresholds so the composite
        # warning/critical are applied to every temperature sensor (matches the
        # C++ daemon).
        ct = raw.get("nvme_composite_temperature_threshold") or {}
        t_warn = ct.get("warning")
        t_crit = ct.get("critical")
        t_warn = int(t_warn) if t_warn is not None else None
        t_crit = int(t_crit) if t_crit is not None else None
        h_temp = h.get("temperature")
        if h_temp is not None:
            sensor(1, 3, "Composite",
                   "nvme_smart_health_information_log.temperature",
                   9, 0, int(h_temp), 1, "Celsius",
                   hi_crit=t_crit, hi_warn=t_warn)
        spare = h.get("available_spare")
        if spare is not None:
            thr = int(h.get("available_spare_threshold") or 10)
            sensor(2, 10, "Available Spare",
                   "nvme_smart_health_information_log.available_spare",
                   9, 0, int(spare), 1, "percent",
                   lo_warn=thr * 2, lo_crit=thr)
        pct_used = h.get("percentage_used")
        if pct_used is not None:
            sensor(3, 10, "Percentage Used",
                   "nvme_smart_health_information_log.percentage_used",
                   9, 0, int(pct_used), 1, "percent")
        for i, t_val in enumerate(h.get("temperature_sensors") or [], start=0):
            if t_val is not None:
                sensor(10 + i, 3, f"Sensor {i + 1}",
                       "nvme_smart_health_information_log.temperature_sensors",
                       9, 0, int(t_val), 1, "Celsius",
                       hi_crit=t_crit, hi_warn=t_warn)
    elif t_current is not None:
        t_crit = int(temp.get("op_limit") or temp.get("limit_max") or 70)
        sensor(1, 3, "temperature", "temperature.current",
               9, 0, int(t_current), 1, "C",
               hi_crit=t_crit, hi_warn=t_crit - 5)

    # Seagate FARM: 4 sensors from page_4_environment_statistics
    farm = raw.get("seagate_farm_log") or {}
    if farm.get("supported"):
        farm_ts = datetime.fromtimestamp(
            int((farm.get("local_time") or {}).get("time_t", 0) or 0),
            tz=timezone.utc,
        ) or poll_time
        env = farm.get("page_4_environment_statistics") or {}
        _FARM_SENSORS = [
            (3, "current_12v_in_mv",   "12V Supply",  6, 8, "mV"),
            (4, "current_5v_in_mv",    "5V Supply",   6, 8, "mV"),
            (5, "humidity",            "Humidity",   10, 9, "percent"),
            (6, "current_motor_power", "Motor Power", 4, 8, "mW"),
        ]
        for s_idx, field, name, stype, scale, units in _FARM_SENSORS:
            val = env.get(field)
            if val is None:
                continue
            sensors.append({
                "idx": s_idx, "type": stype, "name": name,
                "source": f"seagate_farm_log.page_4_environment_statistics.{field}",
                "scale": scale, "precision": 0, "value": int(val),
                "status": 1, "units_display": units,
                "hi_crit": None, "hi_warn": None, "lo_warn": None, "lo_crit": None,
                "timestamp": farm_ts,
            })

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
        # Thresholds the device does not expose are omitted (None -> not in the
        # oid_map), so the custom sensor handler answers noSuchInstance for them
        # rather than reporting a misleading limit of 0.
        add(T+(12, d_idx, si), *_integer(s["hi_crit"]))
        add(T+(13, d_idx, si), *_integer(s["hi_warn"]))
        add(T+(14, d_idx, si), *_integer(s["lo_warn"]))
        add(T+(15, d_idx, si), *_integer(s["lo_crit"]))
    return len(sensors)


# ==========================================================================
# Part 3b — Notifications (SNMP v2 traps)
# ==========================================================================
#
# Mirrors agentxd_notify.cpp + the dispatch logic in agentxd_datasrc.cpp.
# Change detection runs on the worker thread inside _build()/_collect_and_build()
# and enqueues self-contained trap descriptors onto _notify_q; the main thread
# drains the queue and calls send_v2trap() (net-snmp is single-threaded, so all
# socket-touching calls happen on the main thread — see main()).

# Producer/consumer handoff for traps: descriptor = (trap_oid_tuple, varbinds)
# where varbinds is a list of (oid_tuple, kind, value).  kind is one of
# "int"/"uint"/"gauge"/"c64"/"str"/"dt"/"oid".
#
# There is a single AgentX connection to the master and net-snmp is not
# thread-safe, so only ONE thread may ever call libnetsnmp.  The build/worker
# thread does change detection and APPENDS descriptors here (pure Python); the
# main loop POPS them and is the only caller of send_v2trap.  This handoff is the
# only shared state between the threads — no lock is needed.
_notify_q: "queue.Queue[tuple]" = queue.Queue()

# Sensor alarm states (values are arbitrary but must be stable/distinct).
_SENS_NORMAL        = 0
_SENS_HIGH_CRITICAL = 1
_SENS_HIGH_WARNING  = 2
_SENS_LOW_WARNING   = 3
_SENS_LOW_CRITICAL  = 4

# SNMPv2-MIB::snmpTrapOID.0 — first varbind of every v2 trap.
_SNMP_TRAP_OID = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)

# ASN.1 type tags (from net-snmp headers; ASN_GAUGE == ASN_UNSIGNED).
_ASN_INTEGER   = 0x02
_ASN_OCTET_STR = 0x04
_ASN_OBJECT_ID = 0x06
_ASN_UNSIGNED  = 0x42
_ASN_COUNTER64 = 0x46

_trap_api = None   # cached netsnmpapi module with prototypes prepared

# fd_set / timeval mirrors for snmp_select_info(), used to drive the main loop
# with a bounded timeout (Linux: FD_SETSIZE=1024).
_NFDBITS = 8 * ctypes.sizeof(ctypes.c_long)


class _CFdSet(ctypes.Structure):
    _fields_ = [("fds_bits", ctypes.c_long * (1024 // _NFDBITS))]


class _CTimeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


def _get_trap_api():
    """Import netsnmpapi and prepare the C prototypes we call by ctypes (once)."""
    global _trap_api
    if _trap_api is None:
        import netsnmpapi as api
        api.libnsa.send_v2trap.argtypes = [api.netsnmp_variable_list_p]
        api.libnsa.send_v2trap.restype  = ctypes.c_int
        api.libnsa.snmp_free_varbind.argtypes = [api.netsnmp_variable_list_p]
        api.libnsa.snmp_free_varbind.restype  = None
        api.libnsa.snmp_select_info.argtypes = [
            ctypes.POINTER(ctypes.c_int), ctypes.POINTER(_CFdSet),
            ctypes.POINTER(_CTimeval), ctypes.POINTER(ctypes.c_int)]
        api.libnsa.snmp_select_info.restype = ctypes.c_int
        _trap_api = api
    return _trap_api


def _enable_agentx_debug(log_path: str) -> None:
    """Turn on net-snmp's own AgentX PDU tracing (the DEBUG-AGENTX log level).

    Routes net-snmp logging to log_path (or stderr) and enables the 'agentx'
    debug token, so every PDU exchanged with the master agent is written out —
    used to inspect what the master actually sends during a walk."""
    lib = _get_trap_api().libnsa
    lib.snmp_set_do_debugging.argtypes = [ctypes.c_int]
    lib.debug_register_tokens.argtypes = [ctypes.c_char_p]
    if log_path:
        lib.snmp_enable_filelog.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.snmp_enable_filelog(log_path.encode(), 1)   # 1 = append, don't truncate
    else:
        lib.snmp_enable_stderrlog()
    lib.snmp_set_do_debugging(1)
    lib.debug_register_tokens(b"agentx")
    LOGGER.info("AgentX PDU debug tracing enabled (-> %s)", log_path or "stderr")


# Reused ctypes scratch + cached agent fd list for _agent_wait.  snmp_select_info
# and the struct allocation are relatively expensive in Python, so we do NOT run
# them per packet: the subagent's master-socket fd is stable, so we cache the fd
# list and only re-discover it when the select times out (idle) or errors (the fd
# changed, e.g. master reconnect).  During a busy walk select keeps returning the
# live fd readable, so we never re-discover and the per-packet cost is just the
# select itself — back to ~check_and_process(block=True) speed.
_SEL_NUMFDS = ctypes.c_int(0)
_SEL_FDSET  = _CFdSet()
_SEL_TV     = _CTimeval()
_SEL_BLOCK  = ctypes.c_int(0)
_sel_fds: Optional[list] = None      # cached fd list (None = needs discovery)


def _discover_agent_fds(api) -> list:
    _SEL_NUMFDS.value = 0
    ctypes.memset(ctypes.byref(_SEL_FDSET), 0, ctypes.sizeof(_SEL_FDSET))
    _SEL_BLOCK.value = 0
    api.libnsa.snmp_select_info(ctypes.byref(_SEL_NUMFDS), ctypes.byref(_SEL_FDSET),
                                ctypes.byref(_SEL_TV), ctypes.byref(_SEL_BLOCK))
    return [fd for fd in range(_SEL_NUMFDS.value)
            if (_SEL_FDSET.fds_bits[fd // _NFDBITS] >> (fd % _NFDBITS)) & 1]


def _agent_wait(api, max_timeout: float) -> bool:
    """Block until a net-snmp fd is readable or max_timeout elapses.

    Returns True when a packet arrived (fds were readable), False on idle timeout
    or the no-fd/stale-fd paths — the caller uses this to track SNMP request
    bursts.  Keeps the loop responsive to client packets (so walks run at full
    speed) yet wakes at least every max_timeout to flush queued traps/snapshots."""
    global _sel_fds
    if _sel_fds is None:
        _sel_fds = _discover_agent_fds(api)
        # Having live fds means the subagent session to the master is up; surface
        # the connect/disconnect state for the systemd STATUS= line.
        _st.agentx_connected = bool(_sel_fds)
    if not _sel_fds:
        time.sleep(max_timeout)
        _sel_fds = None   # re-discover once the agent's fds appear
        return False
    try:
        ready, _, _ = select.select(_sel_fds, [], [], max_timeout)
    except (OSError, ValueError):
        _sel_fds = None   # stale fd (master reconnect) — rediscover next time
        _st.agentx_connected = False
        return False
    if not ready:
        _sel_fds = None   # idle timeout — cheap moment to refresh the fd list
    return bool(ready)


def _vb_append(api, vars_ref, oid_tuple, kind, value) -> None:
    """Append one varbind to the C variable_list pointed to by vars_ref."""
    name = (api.c_oid * len(oid_tuple))(*oid_tuple)
    if kind == "oid":
        arr = (api.c_oid * len(value))(*value)
        api.libnsa.snmp_varlist_add_variable(
            vars_ref, name, len(oid_tuple), _ASN_OBJECT_ID,
            ctypes.cast(arr, ctypes.c_void_p), len(value) * ctypes.sizeof(api.c_oid))
    elif kind == "int":
        cval = ctypes.c_long(int(value) if value is not None else 0)
        api.libnsa.snmp_varlist_add_variable(
            vars_ref, name, len(oid_tuple), _ASN_INTEGER,
            ctypes.byref(cval), ctypes.sizeof(cval))
    elif kind in ("uint", "gauge"):
        cval = ctypes.c_ulong(int(value) & 0xFFFFFFFF if value is not None else 0)
        api.libnsa.snmp_varlist_add_variable(
            vars_ref, name, len(oid_tuple), _ASN_UNSIGNED,
            ctypes.byref(cval), ctypes.sizeof(cval))
    elif kind == "c64":
        cval = api.counter64(int(value) if value is not None else 0)
        api.libnsa.snmp_varlist_add_variable(
            vars_ref, name, len(oid_tuple), _ASN_COUNTER64,
            ctypes.byref(cval), ctypes.sizeof(cval))
    elif kind in ("str", "dt"):
        if kind == "dt":
            raw = _encode_datetimeval(value) if isinstance(value, datetime) else b""
        elif isinstance(value, bytes):
            raw = value
        else:
            raw = ("" if value is None else str(value)).encode("utf-8", "replace")
        buf = ctypes.create_string_buffer(len(raw) or 1)
        buf.raw = raw.ljust(len(buf), b"\x00")
        api.libnsa.snmp_varlist_add_variable(
            vars_ref, name, len(oid_tuple), _ASN_OCTET_STR, buf, len(raw))
    else:
        raise ValueError(f"unsupported varbind kind {kind!r}")


def _send_trap(trap_oid: tuple, varbinds: list) -> None:
    """Build and send one SNMP v2 trap.  MAIN THREAD ONLY (net-snmp socket)."""
    try:
        api = _get_trap_api()
    except Exception as exc:        # pragma: no cover - missing net-snmp
        LOGGER.error("trap: net-snmp API unavailable: %s", exc)
        return
    vars_p = api.netsnmp_variable_list_p()   # NULL list head
    vars_ref = ctypes.byref(vars_p)
    _vb_append(api, vars_ref, _SNMP_TRAP_OID, "oid", trap_oid)
    for oid_tuple, kind, value in varbinds:
        _vb_append(api, vars_ref, oid_tuple, kind, value)
    api.libnsa.send_v2trap(vars_p)
    api.libnsa.snmp_free_varbind(vars_p)


def _drain_and_send_traps() -> int:
    """Drain _notify_q and send each trap.  MAIN THREAD ONLY (sole net-snmp
    caller).  Returns the number of traps sent."""
    sent = 0
    while True:
        try:
            trap_oid, varbinds = _notify_q.get_nowait()
        except queue.Empty:
            break
        _send_trap(trap_oid, varbinds)
        sent += 1
    return sent


# ---- varbind helpers (device identity columns) ----

def _vb_device_identity(d_idx: int, name: str, path: str) -> list:
    return [
        (_full((2, 1, 3, 1, 2)) + (d_idx,), "str", name),
        (_full((2, 1, 3, 1, 3)) + (d_idx,), "str", path),
    ]


def _vb_disk_identity(d_idx: int, dev: dict) -> list:
    """model_name + serial_number + device_path (NVMe/SATA/SAS traps)."""
    return [
        (_full((2, 1, 3, 1, 11)) + (d_idx,), "str", dev["model_name"]),
        (_full((2, 1, 3, 1, 12)) + (d_idx,), "str", dev["serial_number"]),
        (_full((2, 1, 3, 1, 3))  + (d_idx,), "str", dev["device_path"]),
    ]


def _vb_poll_time(d_idx: int, dev: dict) -> list:
    pt = dev.get("poll_time")
    return [(_full((2, 1, 3, 1, 5)) + (d_idx,), "dt", pt)] if pt else []


# ---- notification builders (enqueue a descriptor) ----

def _notify_device_discovered(d_idx: int, dev: dict) -> None:
    vb = _vb_device_identity(d_idx, dev["name"], dev["device_path"])
    vb.append((_full((2, 1, 3, 1, 4)) + (d_idx,), "int", dev["device_type"]))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full((2, 3, 1)), vb))
    LOGGER.info("notify: device_discovered d_idx=%d path=%s", d_idx, dev["device_path"])


def _notify_device_removed(info: dict) -> None:
    d_idx = info["d_idx"]
    vb = _vb_device_identity(d_idx, info["name"], info["device_path"])
    vb.append((_full((2, 1, 3, 1, 4)) + (d_idx,), "int", info["dev_type"]))
    _notify_q.put((_full((2, 3, 2)), vb))
    LOGGER.info("notify: device_removed d_idx=%d path=%s", d_idx, info["device_path"])


def _notify_device_poll_failed(info: dict) -> None:
    d_idx = info["d_idx"]
    vb = _vb_device_identity(d_idx, info["name"], info["device_path"])
    vb.append((_full((2, 1, 3, 1, 6)) + (d_idx,), "int", _POLL_RESULT["failed"]))
    vb.append((_full((2, 1, 7, 0)), "uint", _st.poll_failure_threshold))
    _notify_q.put((_full((2, 3, 3)), vb))
    LOGGER.notice("notify: device_poll_failed d_idx=%d path=%s", d_idx, info["device_path"])


def _notify_health_changed(d_idx: int, dev: dict, new_status: int) -> None:
    proto = dev["protocol"]
    vb = _vb_disk_identity(d_idx, dev)
    if proto == "nvme":
        trap = _full((3, 2, 1))
        vb.append((_full((3, 1, 15, 1, 1)) + (d_idx, 1), "int", new_status))
        cw = _parse_nvme_health(dev["raw"])["critical_warning"]
        vb.append((_full((3, 1, 15, 1, 2)) + (d_idx, 1), "str", bytes([int(cw) & 0xFF])))
    elif proto in ("ata", "sat"):
        trap = _full((4, 2, 1))
        vb.append((_full((4, 1, 6, 1, 1)) + (d_idx,), "int", new_status))
    else:   # scsi / sas
        trap = _full((5, 2, 1))
        vb.append((_full((5, 1, 6, 1, 1)) + (d_idx, 1), "int", new_status))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((trap, vb))
    LOGGER.notice("notify: health_changed d_idx=%d proto=%s status=%d", d_idx, proto, new_status)


def _notify_nvme_selftest_failed(d_idx: int, dev: dict, st: dict) -> None:
    e  = st["entry"]
    vb = _vb_disk_identity(d_idx, dev)
    vb.append((_full((3, 1, 18, 1, 2)) + (d_idx, e), "gauge", st["number"]))
    vb.append((_full((3, 1, 18, 1, 3)) + (d_idx, e), "int",   st["type"]))
    vb.append((_full((3, 1, 18, 1, 4)) + (d_idx, e), "int",   st["result"]))
    vb.append((_full((3, 1, 18, 1, 5)) + (d_idx, e), "str",   st["result_text"]))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full((3, 2, 2)), vb))
    LOGGER.notice("notify: nvme_selftest_failed d_idx=%d entry=%d", d_idx, e)


def _notify_sata_selftest_failed(d_idx: int, dev: dict, st: dict) -> None:
    e  = st["entry"]
    vb = _vb_disk_identity(d_idx, dev)
    vb.append((_full((4, 1, 18, 1, 2)) + (d_idx, e), "int", st["type"]))
    vb.append((_full((4, 1, 18, 1, 3)) + (d_idx, e), "int", st["result"]))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full((4, 2, 3)), vb))
    LOGGER.notice("notify: sata_selftest_failed d_idx=%d entry=%d", d_idx, e)


def _notify_sata_attr_failing(d_idx: int, dev: dict, a: dict) -> None:
    ai = a["id"]
    vb = _vb_disk_identity(d_idx, dev)
    vb.append((_full((4, 1, 9, 1, 1)) + (d_idx, ai), "uint",  ai))
    vb.append((_full((4, 1, 9, 1, 2)) + (d_idx, ai), "str",   a["name"]))
    vb.append((_full((4, 1, 9, 1, 6)) + (d_idx, ai), "gauge", a["value"]))
    vb.append((_full((4, 1, 9, 1, 8)) + (d_idx, ai), "gauge", a["thresh"]))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full((4, 2, 2)), vb))
    LOGGER.notice("notify: sata_attr_failing d_idx=%d attr=%d value=%d thresh=%d",
             d_idx, ai, a["value"], a["thresh"])


def _notify_sas_uncorrected(d_idx: int, dev: dict, direction: int, count: int) -> None:
    vb = _vb_disk_identity(d_idx, dev)
    vb.append((_full((5, 1, 9, 1, 8)) + (d_idx, direction), "c64", count))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full((5, 2, 3)), vb))
    LOGGER.notice("notify: sas_uncorrected d_idx=%d dir=%d count=%d", d_idx, direction, count)


# Sensor MIB threshold column for each alarm state, and the trap OID suffix.
_SENS_THRESH_COL = {
    _SENS_HIGH_CRITICAL: (12, "hi_crit", (6, 2, 1)),
    _SENS_HIGH_WARNING:  (13, "hi_warn", (6, 2, 2)),
    _SENS_LOW_WARNING:   (14, "lo_warn", (6, 2, 3)),
    _SENS_LOW_CRITICAL:  (15, "lo_crit", (6, 2, 4)),
}


def _notify_sensor_alarm(d_idx: int, dev: dict, s: dict, state: int) -> None:
    si  = s["idx"]
    col, key, trap_suffix = _SENS_THRESH_COL[state]
    vb = _vb_device_identity(d_idx, dev["name"], dev["device_path"])
    vb.append((_full((6, 1, 3, 1, 3)) + (d_idx, si), "str", s["name"]))
    vb.append((_full((6, 1, 3, 1, 2)) + (d_idx, si), "int", s["type"]))
    vb.append((_full((6, 1, 3, 1, 7)) + (d_idx, si), "int", s["value"]))
    vb.append((_full((6, 1, 3, 1, col)) + (d_idx, si), "int", s[key] or 0))
    vb.append((_full((6, 1, 3, 1, 9)) + (d_idx, si), "str", s["units_display"]))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full(trap_suffix), vb))
    LOGGER.notice("notify: sensor alarm d_idx=%d sensor=%s state=%d value=%d",
             d_idx, s["name"], state, s["value"])


def _notify_sensor_recovered(d_idx: int, dev: dict, s: dict) -> None:
    si = s["idx"]
    vb = _vb_device_identity(d_idx, dev["name"], dev["device_path"])
    vb.append((_full((6, 1, 3, 1, 3)) + (d_idx, si), "str", s["name"]))
    vb.append((_full((6, 1, 3, 1, 2)) + (d_idx, si), "int", s["type"]))
    vb.append((_full((6, 1, 3, 1, 7)) + (d_idx, si), "int", s["value"]))
    vb.append((_full((6, 1, 3, 1, 9)) + (d_idx, si), "str", s["units_display"]))
    vb += _vb_poll_time(d_idx, dev)
    _notify_q.put((_full((6, 2, 5)), vb))
    LOGGER.notice("notify: sensor_recovered d_idx=%d sensor=%s", d_idx, s["name"])


# ---- signal extraction (current values used for change detection) ----

def _device_health_status(dev: dict) -> int:
    """overall health enum: 1 passed / 2 failed / 0 unknown (matches health tables)."""
    sp = dev.get("smart_passed")
    return 1 if sp else (2 if sp is False else 0)


def _nvme_failed_selftests(raw: dict) -> List[dict]:
    log     = raw.get("nvme_self_test_log") or {}
    entries = log.get("table") or []
    out = []
    for i, e in enumerate(entries):
        result = e.get("self_test_result") or {}
        if int(result.get("value", 0) or 0) == 0:
            continue
        code = e.get("self_test_code") or {}
        out.append({
            "entry":       i + 1,
            "number":      i + 1,
            "type":        _NVME_ST_TYPE.get(int(code.get("value", 0) or 0), 255),
            "result":      int(result.get("value", 0) or 0),
            "result_text": str(result.get("string") or ""),
        })
    return out


def _sata_failed_selftests(raw: dict) -> List[dict]:
    entries = _sata_selftest_table(raw)
    out = []
    for i, e in enumerate(entries):
        status = e.get("status") or {}
        if status.get("passed", False):
            continue
        st_val  = int((e.get("type") or {}).get("value", 0) or 0)
        raw_res = int(status.get("value", 0) or 0)
        result  = (raw_res + 1) if 0 <= raw_res <= 8 else (15 if raw_res == 15 else 0)
        out.append({
            "entry":  i + 1,
            "type":   _SATA_ST_TYPE.get(st_val, 0),
            "result": result,
        })
    return out


def _compute_sensor_alarm(s: dict, old_state: int, hyst: int) -> int:
    """Port of compute_sensor_alarm_state(): high/low alarm with clear-hysteresis."""
    v = s["value"]
    if s["hi_crit"] is not None:
        stay = old_state == _SENS_HIGH_CRITICAL and v >= s["hi_crit"] - hyst
        if v >= s["hi_crit"] or stay:
            return _SENS_HIGH_CRITICAL
    if s["hi_warn"] is not None:
        stay = old_state == _SENS_HIGH_WARNING and v >= s["hi_warn"] - hyst
        if v >= s["hi_warn"] or stay:
            return _SENS_HIGH_WARNING
    if s["lo_crit"] is not None:
        stay = old_state == _SENS_LOW_CRITICAL and v <= s["lo_crit"] + hyst
        if v <= s["lo_crit"] or stay:
            return _SENS_LOW_CRITICAL
    if s["lo_warn"] is not None:
        stay = old_state == _SENS_LOW_WARNING and v <= s["lo_warn"] + hyst
        if v <= s["lo_warn"] or stay:
            return _SENS_LOW_WARNING
    return _SENS_NORMAL


def _detect_sensor_notifications(d_idx: int, dev: dict, is_new: bool) -> None:
    """Sensor alarm state machine — transitions, hysteresis, periodic resend."""
    now = time.monotonic()
    for s in _extract_sensors(dev):
        key = (d_idx, s["idx"])
        old_state = _st.sensor_alarm_state.get(key, _SENS_NORMAL)

        if _st.test_mode:
            # Test mode: fire unconditionally whenever the sensor is in alarm.
            if s["hi_crit"] is not None and s["value"] >= s["hi_crit"]:
                _notify_sensor_alarm(d_idx, dev, s, _SENS_HIGH_CRITICAL)
            elif s["hi_warn"] is not None and s["value"] >= s["hi_warn"]:
                _notify_sensor_alarm(d_idx, dev, s, _SENS_HIGH_WARNING)
            if s["lo_crit"] is not None and s["value"] <= s["lo_crit"]:
                _notify_sensor_alarm(d_idx, dev, s, _SENS_LOW_CRITICAL)
            elif s["lo_warn"] is not None and s["value"] <= s["lo_warn"]:
                _notify_sensor_alarm(d_idx, dev, s, _SENS_LOW_WARNING)
            continue

        new_state = _compute_sensor_alarm(s, old_state, _st.sensor_hysteresis)

        if is_new:
            # Establish baseline without firing on first sighting.
            _st.sensor_alarm_state[key]     = new_state
            _st.sensor_alarm_last_sent[key] = now
            continue

        if new_state != old_state:
            if new_state == _SENS_NORMAL:
                _notify_sensor_recovered(d_idx, dev, s)
            else:
                _notify_sensor_alarm(d_idx, dev, s, new_state)
            _st.sensor_alarm_state[key]     = new_state
            _st.sensor_alarm_last_sent[key] = now
        elif new_state != _SENS_NORMAL and _st.sensor_resend_interval > 0:
            last = _st.sensor_alarm_last_sent.get(key, 0)
            if now - last >= _st.sensor_resend_interval:
                _notify_sensor_alarm(d_idx, dev, s, new_state)
                _st.sensor_alarm_last_sent[key] = now


def _forget_device_baselines(d_idx: int) -> None:
    """Drop all per-device notification baseline state (device removed)."""
    _st.known_didx.discard(d_idx)
    _st.device_health.pop(d_idx, None)
    _st.failed_selftest.pop(d_idx, None)
    _st.attr_failing.pop(d_idx, None)
    for key in [k for k in _st.sas_uncorrected if k[0] == d_idx]:
        _st.sas_uncorrected.pop(key, None)
    for key in [k for k in _st.sensor_alarm_state if k[0] == d_idx]:
        _st.sensor_alarm_state.pop(key, None)
        _st.sensor_alarm_last_sent.pop(key, None)


def _detect_device_notifications(d_idx: int, dev: dict) -> None:
    """Per-device change detection (health, self-test, attrs, SAS errors, sensors).

    Mirrors capture_snapshot()/dispatch_notifications()/update_alarm_state() in
    agentxd_datasrc.cpp.  On a device's first sighting all baselines are seeded
    and nothing fires (a device-discovered trap is queued by the caller); from
    then on each refresh compares against the stored baseline."""
    proto  = dev["protocol"]
    raw    = dev["raw"]
    is_new = d_idx not in _st.known_didx

    # Current signal values.
    health = _device_health_status(dev)

    if proto == "nvme":
        failed = _nvme_failed_selftests(raw)
    elif proto in ("ata", "sat"):
        failed = _sata_failed_selftests(raw)
    else:
        failed = []
    max_failed = max((f["entry"] for f in failed), default=0)

    attr_failing = set()
    if proto in ("ata", "sat"):
        for a in _parse_sata_attrs(raw):
            if a["thresh"] > 0 and a["value"] <= a["thresh"]:
                attr_failing.add(a["id"])

    sas_counts = {}
    if proto in ("scsi", "sas"):
        for r in _parse_sas_error_counters(raw):
            sas_counts[r["direction"]] = r["uncorrected_errors"]

    if is_new:
        _st.known_didx.add(d_idx)
        _st.device_health[d_idx]   = health
        _st.failed_selftest[d_idx] = max_failed
        _st.attr_failing[d_idx]    = attr_failing
        for direction, cnt in sas_counts.items():
            _st.sas_uncorrected[(d_idx, direction)] = cnt
        _detect_sensor_notifications(d_idx, dev, is_new=True)
        if _st.initial_scan_done:
            _notify_device_discovered(d_idx, dev)
        return

    # Health change.
    prev_health = _st.device_health.get(d_idx)
    if prev_health is not None and prev_health != health:
        _notify_health_changed(d_idx, dev, health)
    _st.device_health[d_idx] = health

    # New self-test failure (highest failed entry advanced).
    if max_failed > _st.failed_selftest.get(d_idx, 0):
        worst = max(failed, key=lambda f: f["entry"])
        if proto == "nvme":
            _notify_nvme_selftest_failed(d_idx, dev, worst)
        elif proto in ("ata", "sat"):
            _notify_sata_selftest_failed(d_idx, dev, worst)
    _st.failed_selftest[d_idx] = max_failed

    # SATA prefailure attribute newly below threshold.
    if proto in ("ata", "sat"):
        prev = _st.attr_failing.get(d_idx, set())
        for a in _parse_sata_attrs(raw):
            if a["thresh"] > 0 and a["value"] <= a["thresh"] and a["id"] not in prev:
                _notify_sata_attr_failing(d_idx, dev, a)
        _st.attr_failing[d_idx] = attr_failing

    # SAS uncorrected error count increased.
    if proto in ("scsi", "sas"):
        for direction, cnt in sas_counts.items():
            base = _st.sas_uncorrected.get((d_idx, direction), 0)
            if cnt > base:
                _notify_sas_uncorrected(d_idx, dev, direction, cnt)
            _st.sas_uncorrected[(d_idx, direction)] = cnt

    _detect_sensor_notifications(d_idx, dev, is_new=False)


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
        "custom_handler": True,
        "indexes": 1,
        "columns": {2: "string", 3: "gauge", 4: "datetimeval"},
    },
    "sata_change_by_device": {
        "oid_suffix": (4, 1, 2, 2),
        "entry_prefix": _full((4, 1, 2, 2, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {2: "gauge", 3: "datetimeval"},
    },
    "sata_change_by_subidx": {
        "oid_suffix": (4, 1, 2, 3),
        "entry_prefix": _full((4, 1, 2, 3, 1)),
        "custom_handler": True,
        "indexes": 3,
        "columns": {4: "datetimeval"},
    },
    "sata_info": {
        "oid_suffix": (4, 1, 3),
        "entry_prefix": _full((4, 1, 3, 1)),
        "custom_handler": True,
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
        "custom_handler": True,   # SMARTMON-COMMON-MIB device table -> NULL semantics
        "columns": {
            2: "string", 3: "string", 4: "integer", 5: "datetimeval",
            6: "integer", 7: "gauge",  8: "integer", 9: "string",
            10: "string", 11: "string", 12: "string", 13: "string", 14: "string",
        },
    },
    "nvme_controller": {
        "oid_suffix": (3, 1, 3),
        "entry_prefix": _full((3, 1, 3, 1)),
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
        "indexes": 2,
        "columns": {
            2: "integer", 3: "gauge", 6: "gauge", 7: "gauge",
            8: "gauge", 9: "gauge", 10: "gauge", 11: "gauge",
        },
    },
    "nvme_lba_format": {
        "oid_suffix": (3, 1, 12),
        "entry_prefix": _full((3, 1, 12, 1)),
        "custom_handler": True,
        "indexes": 3,
        "columns": {
            2: "integer", 3: "gauge", 4: "gauge", 5: "gauge",
        },
    },
    "nvme_health": {
        "oid_suffix": (3, 1, 15),
        "entry_prefix": _full((3, 1, 15, 1)),
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
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
        "custom_handler": True,
        "indexes": 2,
        "columns": {
            2: "integer", 3: "integer", 4: "integer",
            5: "gauge", 6: "counter64", 7: "counter64",
        },
    },
    "sata_erc": {
        "oid_suffix": (4, 1, 21),
        "entry_prefix": _full((4, 1, 21, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {2: "integer", 3: "gauge"},
    },
    "sata_phyevent": {
        "oid_suffix": (4, 1, 24),
        "entry_prefix": _full((4, 1, 24, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {2: "string", 3: "gauge", 4: "counter64", 5: "integer"},
    },
    "sata_selective": {
        "oid_suffix": (4, 1, 27),
        "entry_prefix": _full((4, 1, 27, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {2: "counter64", 3: "counter64", 4: "gauge"},
    },
    "sata_logdir": {
        "oid_suffix": (4, 1, 34),
        "entry_prefix": _full((4, 1, 34, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {2: "string", 3: "integer", 4: "integer", 5: "gauge", 6: "gauge"},
    },
    "sata_devstat": {
        "oid_suffix": (4, 1, 40),
        "entry_prefix": _full((4, 1, 40, 1)),
        "custom_handler": True,
        "indexes": 3,
        "columns": {3: "string", 4: "string", 5: "counter64", 6: "bits"},
    },
    "sata_pending_defects": {
        "oid_suffix": (4, 1, 43),
        "entry_prefix": _full((4, 1, 43, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {2: "counter64"},
    },
    "sas_health": {
        "oid_suffix": (5, 1, 6),
        "entry_prefix": _full((5, 1, 6, 1)),
        "custom_handler": True,
        "indexes": 2,
        "columns": {
            1: "integer", 2: "gauge", 3: "counter64", 4: "integer", 5: "gauge",
        },
    },
    "sas_err": {
        "oid_suffix": (5, 1, 9),
        "entry_prefix": _full((5, 1, 9, 1)),
        "custom_handler": True,
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
        # Served by a custom oid_map-backed handler (_register_sensor_handler),
        # not net-snmp's dense table_dataset, so unset cells answer
        # noSuchInstance (RFC 1905) instead of a fabricated column default.
        "custom_handler": True,
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
    LOGGER.info("registered %d scalars", len(scalars))
    return scalars


def _register_tables(agent: Any) -> Dict[str, Any]:
    tables = {}
    for name, defn in TABLE_DEFINITIONS.items():
        if defn.get("custom_handler"):
            continue            # served by a custom handler, not table_dataset
        columns = [
            (col, _make_value(agent, snmp_type, "" if snmp_type in ("string", "datetimeval", "bits") else 0))
            for col, snmp_type in defn["columns"].items()
        ]
        tables[name] = agent.Table(
            oidstr=_table_oid(defn["oid_suffix"]),
            indexes=[agent.Unsigned32() for _ in range(defn["indexes"])],
            columns=columns,
        )
    LOGGER.info("registered %d tables", len(tables))
    return tables


def _publish_scalars(scalars: Dict[Oid, Any], oid_map: dict) -> None:
    now = datetime.now(timezone.utc)
    defns = _scalar_definitions()
    for oid, scalar in scalars.items():
        snmp_type, value = oid_map.get(oid, (None, None))
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


def _publish_tables(agent: Any, tables: Dict[str, Any], oid_map: dict) -> None:
    # Bucket every OID into its table in a single pass over oid_map (O(M))
    # instead of rescanning the whole map once per table (O(tables * M)).
    # Table entry prefixes have only a couple of distinct lengths, so each
    # OID is probed against that small set of prefix slices.
    ctx: Dict[str, dict] = {}            # name -> {table, columns, index_count, rows}
    prefix_to_name: Dict[Tuple, str] = {}
    prefix_lens: set = set()
    for name, table in tables.items():
        defn   = TABLE_DEFINITIONS[name]
        prefix = defn["entry_prefix"]
        prefix_to_name[prefix] = name
        prefix_lens.add(len(prefix))
        ctx[name] = {"table":       table,
                     "columns":     defn["columns"],
                     "index_count": defn["indexes"],
                     "rows":        {}}
    probe_lens = sorted(prefix_lens)

    for oid, (snmp_type, value) in oid_map.items():
        for plen in probe_lens:
            name = prefix_to_name.get(oid[:plen])
            if name is None:
                continue
            c    = ctx[name]
            rest = oid[plen:]
            if len(rest) != c["index_count"] + 1 or rest[0] not in c["columns"]:
                continue
            c["rows"].setdefault(rest[1:], {})[rest[0]] = (snmp_type, value)
            break

    for name, c in ctx.items():
        rows    = c["rows"]
        columns = c["columns"]
        table   = c["table"]

        # Skip the net-snmp rebuild when this table's content is identical to
        # what we last pushed — avoids the per-cell setRowCell() C-call storm
        # for tables that are static between refreshes. The previously
        # published rows stay registered and continue serving requests.
        fp = _rows_fingerprint(rows)
        if fp == _st.published_fp.get(name):
            continue
        _st.published_fp[name] = fp

        table.clear()
        for indexes in sorted(rows):
            row = table.addRow([agent.Unsigned32(idx) for idx in indexes])
            for col, snmp_type in columns.items():
                vtype, val = rows[indexes].get(col, (snmp_type, "" if snmp_type in ("string", "datetimeval", "bits") else 0))
                row.setRowCell(col, _make_value(agent, vtype, val))


def _log_published(n_oids: int, elapsed: float) -> None:
    """Log a publish at INFO only when the OID count changed since the last INFO
    line; otherwise VERBOSE. Keeps steady-state collect-mode polls from repeating
    'published N OIDs' every cycle when nothing was added or removed."""
    if n_oids != _st.last_published_oids:
        LOGGER.info("published %d OIDs in %.2fs", n_oids, elapsed)
        _st.last_published_oids = n_oids
    else:
        LOGGER.verbose("published %d OIDs in %.2fs", n_oids, elapsed)


def _refresh_and_publish(agent: Any, scalars: Dict[Oid, Any], tables: Dict[str, Any]) -> None:
    """Synchronous refresh + publish on the main thread.

    Used for the initial publish at startup and for `--once`. In daemon mode the
    steady-state refresh runs on the worker thread (_collector_loop) and publish
    is driven from the queued snapshot in main()."""
    before = time.monotonic()
    _refresh()
    _publish(agent, scalars, tables, _st.oid_map)
    _log_published(len(_st.oid_map), time.monotonic() - before)


# ==========================================================================
# Custom table handlers (tables flagged "custom_handler" in TABLE_DEFINITIONS)
#
# netsnmpagent.Table is built on net-snmp's table_dataset helper, which is
# dense by design: every registered column is materialised in every row from
# the column defaults, so an unset cell serves a fabricated 0/"".  A MIB that
# needs a missing value (e.g. a threshold the device does not expose) to read
# as an RFC 1905 IMPLICIT NULL therefore serves its table subtree(s) here
# instead, with a raw net-snmp Node_Handler backed directly by the (already
# sparse) oid_map: present cells return their value, a GET miss returns
# noSuchInstance/noSuchObject, and GETNEXT skips absent cells so walks stay
# correct.  AgentX (RFC 2741 §5.4) carries these exception types natively —
# nothing in the protocol or snmpd changes; only these subtrees bypass
# table_dataset.  One shared handler serves every registered subtree; GETNEXT
# is constrained to the registration's own region (reginfo->rootoid).
# ==========================================================================

# net-snmp request modes (agent/snmp_agent.h) and the RFC 1905 exception values.
_MODE_GET          = 160           # SNMP_MSG_GET
_MODE_GETNEXT      = 161           # SNMP_MSG_GETNEXT
# RFC 1905 §4.2.1 VarBind value exceptions (asn1.h), both IMPLICIT NULL:
#   noSuchObject[0]   — the OID prefix matches no accessible variable (column)
#   noSuchInstance[1] — the column exists but this row has no such instance
_SNMP_NOSUCHOBJECT   = 0x80
_SNMP_NOSUCHINSTANCE = 0x81

# Tables served by the custom handler, derived once from TABLE_DEFINITIONS.
_CUSTOM_TABLES = [(name, defn) for name, defn in TABLE_DEFINITIONS.items()
                  if defn.get("custom_handler")]
# entry-prefix tuple -> frozenset(column numbers), for the noSuchInstance vs
# noSuchObject decision and for projecting the subtree out of the oid_map.
_CUSTOM_ENTRY_COLS = {defn["entry_prefix"]: frozenset(defn["columns"])
                      for _, defn in _CUSTOM_TABLES}
_CUSTOM_ENTRY_LENS = sorted({len(ep) for ep in _CUSTOM_ENTRY_COLS})

_custom_api: Any = None             # cached (netsnmpapi, libnetsnmp core)
_custom_handler_cb: Any = None      # kept alive: CFUNCTYPE net-snmp retains


class _NsVarList(ctypes.Structure):
    pass
_NsVarList_p = ctypes.POINTER(_NsVarList)
# Mirror of struct variable_list (net-snmp types.h). The value is a union of
# pointers (one machine word); we never read it (net-snmp copies our value in),
# so c_void_p models it for layout. oid == unsigned long (see netsnmpapi.c_oid).
_NsVarList._fields_ = [
    ("next_variable", _NsVarList_p),
    ("name",          ctypes.POINTER(ctypes.c_ulong)),
    ("name_length",   ctypes.c_size_t),
    ("type",          ctypes.c_ubyte),
    ("val",           ctypes.c_void_p),
    ("val_len",       ctypes.c_size_t),
    ("name_loc",      ctypes.c_ulong * 128),   # MAX_OID_LEN
    ("buf",           ctypes.c_ubyte * 40),
    ("data",          ctypes.c_void_p),
    ("dataFreeHook",  ctypes.c_void_p),
    ("index",         ctypes.c_int),
]


class _NsRequestInfo(ctypes.Structure):
    pass
_NsRequestInfo_p = ctypes.POINTER(_NsRequestInfo)
_NsRequestInfo._fields_ = [
    ("requestvb",       _NsVarList_p),
    ("parent_data",     ctypes.c_void_p),
    ("agent_req_info",  ctypes.c_void_p),
    ("range_end",       ctypes.POINTER(ctypes.c_ulong)),
    ("range_end_len",   ctypes.c_size_t),
    ("delegated",       ctypes.c_int),
    ("processed",       ctypes.c_int),
    ("inclusive",       ctypes.c_int),
    ("status",          ctypes.c_int),
    ("index",           ctypes.c_int),
    ("repeat",          ctypes.c_int),
    ("orig_repeat",     ctypes.c_int),
    ("requestvb_start", _NsVarList_p),
    ("next",            _NsRequestInfo_p),
    ("prev",            _NsRequestInfo_p),
    ("subtree",         ctypes.c_void_p),
]


class _NsAgentReqInfo(ctypes.Structure):
    _fields_ = [
        ("mode",       ctypes.c_int),
        ("asp",        ctypes.c_void_p),
        ("agent_data", ctypes.c_void_p),
    ]
_NsAgentReqInfo_p = ctypes.POINTER(_NsAgentReqInfo)

# int handler(mib_handler*, handler_registration*, agent_request_info*, request_info*)
_NODE_HANDLER = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
    _NsAgentReqInfo_p, _NsRequestInfo_p)


def _get_custom_api():
    """Prepare (once) and cache the ctypes entry points the custom handler needs.
    snmp_set_var_* live in libnetsnmp (core); registration in libnetsnmpagent."""
    global _custom_api
    if _custom_api is not None:
        return _custom_api
    import netsnmpapi as api
    core = ctypes.CDLL(ctypes.util.find_library("netsnmp"))
    core.snmp_set_var_typed_value.argtypes = [
        _NsVarList_p, ctypes.c_ubyte, ctypes.c_void_p, ctypes.c_size_t]
    core.snmp_set_var_typed_value.restype = ctypes.c_int
    core.snmp_set_var_objid.argtypes = [
        _NsVarList_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_size_t]
    core.snmp_set_var_objid.restype = ctypes.c_int
    api.libnsa.netsnmp_register_handler.argtypes = [api.netsnmp_handler_registration_p]
    api.libnsa.netsnmp_register_handler.restype  = ctypes.c_int
    api.libnsa.netsnmp_inject_handler.argtypes = [
        api.netsnmp_handler_registration_p, api.netsnmp_mib_handler_p]
    api.libnsa.netsnmp_inject_handler.restype = ctypes.c_int
    api.libnsa.netsnmp_get_bulk_to_next_handler.argtypes = []
    api.libnsa.netsnmp_get_bulk_to_next_handler.restype = api.netsnmp_mib_handler_p
    _custom_api = (api, core)
    return _custom_api


_CLONG_SIZE = ctypes.sizeof(ctypes.c_long)
# reginfo pointer address -> its rootoid region tuple (regions are stable for the
# life of a registration, so the tuple is built once per table, not per request).
_region_cache: Dict[int, tuple] = {}


def _custom_cvalue(api: Any, stype: str, value: object) -> tuple:
    """Pre-render an oid_map (type, value) into (asn_type, value_arg, value_len)
    ready to pass straight to snmp_set_var_typed_value in the hot path.

    value_arg is bytes (octet-string family) or a ctypes byref to a kept-alive
    scalar (integer family); the byref holds its target alive, so it stays valid
    as long as the view dict does.  Doing this once per publish keeps the
    per-request handler allocation-free."""
    if stype == "integer":
        return (api.ASN_INTEGER, ctypes.byref(ctypes.c_long(int(value))), _CLONG_SIZE)
    if stype == "gauge":
        return (api.ASN_UNSIGNED,
                ctypes.byref(ctypes.c_long(int(value) & 0xFFFFFFFF)), _CLONG_SIZE)
    if stype == "counter64":
        c = api.counter64(); v = int(value)
        c.high, c.low = (v >> 32) & 0xFFFFFFFF, v & 0xFFFFFFFF
        return (api.ASN_COUNTER64, ctypes.byref(c), ctypes.sizeof(c))
    if stype == "string":
        b = _as_text(value).encode();                       return (api.ASN_OCTET_STR, b, len(b))
    if stype == "bits":
        b = bytes(value) if isinstance(value, (bytes, bytearray)) else b""
        return (api.ASN_OCTET_STR, b, len(b))
    if stype == "datetimeval":
        b = _encode_datetimeval(value) if isinstance(value, datetime) else b""
        return (api.ASN_OCTET_STR, b, len(b))
    raise ValueError(f"unsupported SNMP type {stype!r}")


def _custom_tables_view(oid_map: dict) -> tuple:
    """Project every custom-handler table out of an oid_map snapshot into
    (vals, oids).  vals maps full-OID-tuple -> (asn_type, value_arg, value_len,
    name_array, name_len), all pre-rendered so the request handler only makes the
    two net-snmp C calls; oids is the sorted key list for GETNEXT lookup."""
    api, _ = _get_custom_api()
    entry_cols = _CUSTOM_ENTRY_COLS
    lens       = _CUSTOM_ENTRY_LENS
    vals: Dict[tuple, tuple] = {}
    for oid, (stype, value) in oid_map.items():
        for plen in lens:
            if len(oid) > plen and oid[:plen] in entry_cols:
                asn, varg, vlen = _custom_cvalue(api, stype, value)
                nlen = len(oid)
                name = (ctypes.c_ulong * nlen)(*oid)
                vals[oid] = (asn, varg, vlen, name, nlen)
                break
    return vals, sorted(vals)


def _custom_known_column(cur: tuple) -> bool:
    """True if cur addresses a defined column of some custom table (so a GET miss
    is noSuchInstance rather than noSuchObject)."""
    for ep, cols in _CUSTOM_ENTRY_COLS.items():
        if len(cur) > len(ep) and cur[:len(ep)] == ep and cur[len(ep)] in cols:
            return True
    return False


def _custom_node_handler(handler, reginfo, reqinfo, requests) -> int:
    """Shared net-snmp Node_Handler for every custom table. MAIN THREAD ONLY
    (invoked from the agent's request processing in the select loop).  The hot
    path is kept lean: prebuilt value/OID buffers, cached region, and the two
    net-snmp setters bound to locals."""
    try:
        api, core = _get_custom_api()
        set_typed = core.snmp_set_var_typed_value
        set_objid = core.snmp_set_var_objid
        mode = reqinfo.contents.mode
        vals = _st.custom_vals
        oids = _st.custom_oids
        # GETNEXT successors are constrained to this registration's own region so
        # we never hand the master an OID outside the subtree it asked about.
        regaddr = ctypes.cast(reginfo, ctypes.c_void_p).value
        region  = _region_cache.get(regaddr)
        if region is None:
            reg = ctypes.cast(reginfo, api.netsnmp_handler_registration_p).contents
            region = tuple(reg.rootoid[i] for i in range(reg.rootoid_len))
            _region_cache[regaddr] = region
        rlen = len(region)
        req  = requests
        if mode == _MODE_GETNEXT:
            while req:
                rc = req.contents
                vb = rc.requestvb
                v  = vb.contents
                cur = tuple(v.name[:v.name_length])
                # inclusive (region edge) -> first key >= cur; else first > cur.
                idx = (bisect.bisect_left(oids, cur) if rc.inclusive
                       else bisect.bisect_right(oids, cur))
                if idx < len(oids):
                    nxt = oids[idx]
                    if nxt[:rlen] == region:
                        asn, varg, vlen, name, nlen = vals[nxt]
                        set_objid(vb, name, nlen)
                        set_typed(vb, asn, varg, vlen)
                # else: leave varbind untouched -> agent returns endOfMibView,
                # so the walk moves on to the next registered region.
                req = rc.next
        elif mode == _MODE_GET:
            while req:
                rc = req.contents
                vb = rc.requestvb
                v  = vb.contents
                cur = tuple(v.name[:v.name_length])
                cell = vals.get(cur)
                if cell is None:
                    exc = (_SNMP_NOSUCHINSTANCE if _custom_known_column(cur)
                           else _SNMP_NOSUCHOBJECT)
                    set_typed(vb, exc, None, 0)
                else:
                    set_typed(vb, cell[0], cell[1], cell[2])
                req = rc.next
    except Exception:
        LOGGER.exception("custom table handler failure")
    return 0   # SNMP_ERR_NOERROR


def _register_custom_handlers() -> None:
    """Register the shared read-only handler for every custom-handler table
    subtree.  Call after the agent is constructed (net-snmp initialised) and
    before agent.start()."""
    global _custom_handler_cb
    if not _CUSTOM_TABLES:
        return
    api, _ = _get_custom_api()
    _custom_handler_cb = _NODE_HANDLER(_custom_node_handler)   # keep alive
    for name, defn in _CUSTOM_TABLES:
        root    = _full(defn["oid_suffix"])
        reg_oid = (ctypes.c_ulong * len(root))(*root)
        reginfo = api.libnsa.netsnmp_create_handler_registration(
            f"smartmon_{name}".encode(), ctypes.cast(_custom_handler_cb, ctypes.c_void_p),
            reg_oid, len(root), api.HANDLER_CAN_RONLY)
        if not reginfo:
            raise RuntimeError(f"netsnmp_create_handler_registration failed for {name}")
        # Auto-convert GETBULK into GETNEXT so the handler only sees GET/GETNEXT.
        api.libnsa.netsnmp_inject_handler(reginfo, api.libnsa.netsnmp_get_bulk_to_next_handler())
        rc = api.libnsa.netsnmp_register_handler(reginfo)
        if rc != 0:
            raise RuntimeError(f"netsnmp_register_handler failed for {name} (rc={rc})")
    LOGGER.info("registered %d custom table handler(s): %s", len(_CUSTOM_TABLES),
                ", ".join(name for name, _ in _CUSTOM_TABLES))


def _publish(agent: Any, scalars: Dict[Oid, Any], tables: Dict[str, Any],
             oid_map: dict) -> None:
    """Push one oid_map snapshot to net-snmp. MAIN THREAD ONLY (net-snmp is not
    thread-safe)."""
    _publish_scalars(scalars, oid_map)
    _publish_tables(agent, tables, oid_map)
    # Refresh the custom handler's view (custom tables are not in `tables`).
    _st.custom_vals, _st.custom_oids = _custom_tables_view(oid_map)


# Floor for the worker poll interval when TTL is 0 (poll-as-fast-as-possible).
# Prevents a busy loop while keeping trap latency well inside the integration
# test's wait window.  CI runs with ttl=0 for fast trap delivery; production
# sets a larger TTL to trade trap/refresh latency for lower idle cost.
NOTIFY_POLL_INTERVAL = 0.05
# Seconds of SNMP inactivity after which the main loop prints a VERBOSE summary
# of the just-finished activity burst (start line + socket-wakeup count/rate).
SNMP_IDLE_SUMMARY_SEC = 10.0


def _udev_monitor_loop(stop: threading.Event) -> None:
    """Watch the kernel for block-device hotplug events (collect mode only).

    Runs `udevadm monitor --kernel --udev --property --subsystem-match=block`,
    which streams one blank-line-separated property block per event.  When a
    whole disk (DEVTYPE=disk) is added or removed it sets _rescan_event and wakes
    the collector, so the drive set is re-scanned on hotplug instead of on every
    poll.  If udevadm is unavailable the collector falls back to per-cycle
    discovery (collect_specs forced to None)."""
    cmd = ["udevadm", "monitor", "--kernel", "--udev", "--property",
           "--subsystem-match=block"]
    LOGGER.info("udev monitor started")
    # If udevadm exits almost immediately it cannot watch for events (e.g. its
    # NETLINK_KOBJECT_UEVENT socket is blocked by sandboxing — see
    # RestrictAddressFamilies in the systemd unit).  Count such fast exits and,
    # after a few, give up and fall back to per-poll discovery rather than
    # respawning every 5s and spamming the log.
    quick_exits = 0
    while not stop.is_set():
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except OSError as exc:
            LOGGER.warning("udevadm monitor unavailable (%s); falling back to "
                           "per-poll drive discovery", exc)
            _st.collect_specs = None
            return
        _st.udev_proc = proc
        started = time.monotonic()
        action = devtype = None
        try:
            for line in proc.stdout:               # blocks until next line
                if stop.is_set():
                    break
                line = line.strip()
                if not line:                       # blank line ends an event block
                    if action in ("add", "remove") and devtype == "disk":
                        LOGGER.info("udev %s of a disk — scheduling drive rescan",
                                    action)
                        _rescan_event.set()
                        _refresh_request.set()     # wake the collector promptly
                    action = devtype = None
                    continue
                if line.startswith("ACTION="):
                    action = line[len("ACTION="):]
                elif line.startswith("DEVTYPE="):
                    devtype = line[len("DEVTYPE="):]
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
        if stop.is_set():
            break
        if time.monotonic() - started < 3.0:
            quick_exits += 1
            if quick_exits >= 3:
                LOGGER.warning("udevadm monitor keeps exiting immediately "
                               "(check AF_NETLINK is permitted by the unit's "
                               "RestrictAddressFamilies); falling back to "
                               "per-poll drive discovery")
                _st.collect_specs = None
                return
        else:
            quick_exits = 0
        LOGGER.warning("udevadm monitor exited; restarting in 5s")
        stop.wait(5.0)


def _collector_loop(stop: threading.Event) -> None:
    """Producer thread: owns all data collection and _st mutation.

    The TTL is the poll interval: the worker re-stats the state files every
    `_st.ttl` seconds (or every NOTIFY_POLL_INTERVAL when ttl=0) to detect
    changes.  A change runs _refresh() (discover→parse→_build, pure Python + file
    IO); change detection inside _build() appends trap descriptors onto _notify_q
    and the rebuilt oid_map onto _publish_q.  The main loop pops both and is the
    sole net-snmp caller — this thread never touches net-snmp."""
    LOGGER.info("collector thread started")
    while not stop.is_set():
        poll_interval = _st.ttl if _st.ttl > 0 else NOTIFY_POLL_INTERVAL
        # wait() returns early only on shutdown (_refresh_request set in finally).
        _refresh_request.wait(timeout=poll_interval)
        _refresh_request.clear()
        if stop.is_set():
            break

        modified = _files_modified()
        # Stamp the poll and ask the main thread to refresh the systemd STATUS=
        # line every cycle — the "updated" timestamp proves the agent is still
        # polling, so it must advance even when the data is unchanged.  The
        # net-snmp republish below stays gated on a real content change.
        _st.last_update_ts = datetime.now(timezone.utc)
        _status_event.set()

        if not modified:
            continue

        prev_map = _st.oid_map
        _st.last_load = 0.0              # a change forces a rebuild past the guard
        _refresh()

        # _build() rebinds _st.oid_map to a brand-new dict only when it actually
        # rebuilt; on the keep-last-good error path the identity is unchanged,
        # so we skip the redundant publish.
        if _st.oid_map is not prev_map:
            _publish_q.put(_st.oid_map)
    LOGGER.info("collector thread stopped")


def _set_error_scalar(code: int, message: str) -> None:
    pass  # no top-level error scalars in this MIB


def _handle_collection_error(exc: CollectionError, ts: datetime) -> None:
    LOGGER.error("collection error %d: %s", exc.code, exc.message)
    if exc.code in _CLEANUP_CODES or not _st.oid_keys:
        _build([], ts, exc.code, str(exc))


def _collect_and_build(ts: datetime) -> None:
    # Collect mode pulls smartctl directly and parses in-memory (no state_dir);
    # file mode globs state_dir and parses the JSON files.  Both produce a list
    # of (key, device-dict) pairs that the shared removal/build logic consumes.
    t0 = time.monotonic()
    if _st.collect:
        collected = _collect_all()
        t1 = time.monotonic()
        items   = [(key, _parse_device_from_raw(raw, key)) for key, raw in collected]
        present = {key for key, _ in collected}
    else:
        files   = _discover_devices(_st.state_dir, _st.config_devices)
        t1 = time.monotonic()
        items   = [(path, _parse_device_json(path)) for path in files]
        present = set(files)
    t2 = time.monotonic()

    # Removal: a device whose key disappeared since the last cycle.  In collect
    # mode a drive that fails to pull is simply absent and counts as removed.
    for key in [p for p in _st.file_identity if p not in present]:
        info = _st.file_identity.pop(key)
        _st.consec_fail.pop(key, None)
        if _st.initial_scan_done:
            _notify_device_removed(info)
        _forget_device_baselines(info["d_idx"])

    devices = []
    errors  = 0
    for key, dev in items:
        if dev["read_error"]:
            LOGGER.warning("parse error %s: %s", key, dev["read_error"])
            errors += 1
            # Poll failure: file still present but unparseable.  Fire once the
            # consecutive-failure count reaches the configured threshold.
            info = _st.file_identity.get(key)
            if info:
                _st.consec_fail[key] = _st.consec_fail.get(key, 0) + 1
                if _st.consec_fail[key] >= _st.poll_failure_threshold:
                    _notify_device_poll_failed(info)
        else:
            _st.consec_fail.pop(key, None)
            devices.append(dev)
    err_code = EXIT_PARTIAL_FAILURE if errors else EXIT_SUCCESS
    err_msg  = f"{errors} device(s) failed to parse" if errors else ""
    _build(devices, ts, err_code, err_msg)
    LOGGER.verbose("refresh timing: collect %.3fs, parse %.3fs, build %.3fs "
                   "(%d devices)", t1 - t0, t2 - t1, time.monotonic() - t2, len(devices))
    if errors:
        LOGGER.notice("built OID table: %d devices (%d errors)", len(devices), errors)
    elif len(devices) != _st.last_built_devices:
        LOGGER.info("built OID table: %d devices", len(devices))
        _st.last_built_devices = len(devices)
    else:
        LOGGER.verbose("built OID table: %d devices", len(devices))


def _file_signature(path: str) -> Optional[tuple]:
    """Cheap stat signature (size, mtime, ctime) for change detection.

    mtime alone is unreliable: the integration harness swaps fixtures with
    shutil.copy2, which preserves the *source* mtime, and the variant fixtures
    all share one mtime — so a content swap can land on an identical/older mtime
    and go undetected.  ctime closes that gap: it is kernel-controlled and can't
    be set from userspace, so an overwrite always bumps it to "now" even when
    mtime is preserved.  This stays a single stat() (no file read), so it adds no
    load at the sub-second worker poll cadence.  Returns None on stat failure."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_size, st.st_mtime, st.st_ctime)


def _snapshot_file_mtimes() -> None:
    """Record current fixture file signatures so _files_modified() has a baseline."""
    if _st.collect:
        return  # no state_dir files in collect mode
    try:
        files = _discover_devices(_st.state_dir, _st.config_devices)
    except CollectionError:
        return
    _st.file_mtimes.clear()
    # Sidecar FARM files are not device paths but must still trigger a rebuild
    # when they change, so sign them alongside the device files.
    for path in files + list(_st.farm_sidecars.values()):
        sig = _file_signature(path)
        if sig is not None:
            _st.file_mtimes[path] = sig


def _files_modified() -> bool:
    """Return True if any fixture file has been added, removed, or modified since last snapshot."""
    if _st.collect:
        return True  # collect mode polls smartctl every cycle; no mtime gate
    if not _st.file_mtimes:
        return False
    try:
        files = _discover_devices(_st.state_dir, _st.config_devices)
    except CollectionError:
        return False
    current: dict = {}
    for path in files + list(_st.farm_sidecars.values()):
        sig = _file_signature(path)
        if sig is not None:
            current[path] = sig
    changed = current != _st.file_mtimes
    if changed:
        _st.file_mtimes.clear()
        _st.file_mtimes.update(current)
    return changed


def _refresh() -> None:
    now = time.monotonic()
    if _st.oid_keys and now - _st.last_load < _st.ttl:
        LOGGER.debug("cache hit (age=%.1fs ttl=%ds)", now - _st.last_load, _st.ttl)
        return
    LOGGER.verbose("refreshing data (age=%.1fs ttl=%ds)",
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
    finally:
        _snapshot_file_mtimes()
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
        LOGGER.warning("could not read config %s: %s", path, exc, exc_info=True)
    return cfg


def _configure_smartmon(args: "argparse.Namespace", cfg: dict) -> None:
    ttl       = args.cache_timeout if args.cache_timeout is not None else int(cfg.get("cache_timeout", CACHE_TTL))
    log_level = args.log_level or str(cfg.get("log_level", "WARNING")).upper()
    log_path  = args.log_file  or cfg.get("log_file")
    devices   = cfg.get("devices")

    _st.ttl           = ttl
    _st.state_dir     = args.state_dir or cfg.get("state_dir", "")
    _st.config_devices = list(devices) if devices else None
    _st.collect       = bool(args.collect) or \
        str(cfg.get("collect", "")).lower() in ("1", "true", "yes")

    # Notification config (mirror of the C++ AgentxConfig keys).
    def _cfg_int(key, default):
        try:
            return int(cfg.get(key, default))
        except (TypeError, ValueError):
            return default

    _st.poll_failure_threshold  = max(1, _cfg_int("poll_failure_threshold", 1))
    _st.sensor_resend_interval  = max(0, _cfg_int("sensor_resend_interval", 0))
    _st.sensor_hysteresis       = max(0, _cfg_int("sensor_hysteresis", 0))
    _st.test_mode               = str(cfg.get("test_mode", "")).lower() in ("1", "true", "yes")

    # DEBUG-AGENTX is DEBUG plus net-snmp AgentX PDU tracing (enabled in main()
    # via _enable_agentx_debug once the ctypes API is ready).
    _st.agentx_debug = log_level == "DEBUG-AGENTX"
    _st.log_path     = log_path or ""
    level = {"VERBOSE": VERBOSE, "NOTICE": NOTICE, "DEBUG-AGENTX": logging.DEBUG}.get(
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


# --------------------------------------------------------------------------
# systemd sd_notify protocol (Type=notify / WatchdogSec=)
#
# Implemented inline with stdlib `socket` — no dependency — matching this file's
# self-contained design.  Every call is a no-op when $NOTIFY_SOCKET is unset
# (i.e. not run under systemd), and never raises: a notify failure must not
# disturb data serving.
# --------------------------------------------------------------------------

def _sd_notify(state: str) -> bool:
    """Send one datagram to the systemd notify socket ($NOTIFY_SOCKET).

    Returns True if sent, False when off-systemd or on error.  `state` is a
    newline-separated set of FIELD=value lines (e.g. "READY=1", "STOPPING=1",
    "WATCHDOG=1", "STATUS=...")."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr[0] == "@":                 # Linux abstract namespace socket
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.connect(addr)
            sock.sendall(state.encode("utf-8"))
        return True
    except OSError as exc:
        LOGGER.debug("sd_notify(%r) failed: %s", state, exc)
        return False


def _sd_status_text() -> str:
    """Compose the STATUS= line shown by `systemctl status`.

    'v<ver> agentx <state>; <N> disks, <M> OIDs; updated <ts>'.  An active
    collection error is surfaced first so it becomes the headline."""
    conn    = "connected" if _st.agentx_connected else "disconnected"
    n_disks = _st.last_device_count
    n_oids  = len(_st.oid_map)
    updated = (_st.last_update_ts.strftime("%Y-%m-%d %H:%M:%SZ")
               if _st.last_update_ts is not None else "never")
    summary = (f"v{VERSION} agentx {conn}; "
               f"{n_disks} disk{'' if n_disks == 1 else 's'}, "
               f"{n_oids} OIDs; updated {updated}")
    if _st.last_err_code != EXIT_SUCCESS and _st.last_err_msg:
        return f"ERROR: {_st.last_err_msg} | {summary}"
    return summary


def _sd_notify_status(extra: str = "") -> None:
    """Push a STATUS= update, optionally shipping another field (e.g. READY=1)
    in the same datagram."""
    payload = f"STATUS={_sd_status_text()}"
    if extra:
        payload = extra + "\n" + payload
    _sd_notify(payload)


def _sd_watchdog_interval() -> float:
    """Ping period (seconds) for the systemd watchdog, or 0.0 when disabled.

    WATCHDOG_USEC is the unit's WatchdogSec in microseconds; we ping at half that
    (the systemd convention).  WATCHDOG_PID, when set, must match our PID — the
    env can be inherited by child processes that must not answer the watchdog."""
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec:
        return 0.0
    wpid = os.environ.get("WATCHDOG_PID")
    if wpid and wpid != str(os.getpid()):
        return 0.0
    try:
        return max(0.0, int(usec) / 1_000_000.0 / 2.0)
    except ValueError:
        return 0.0


# Signals that should trigger an orderly shutdown: Ctrl-C (SIGINT), systemd /
# `kill` stop (SIGTERM), and terminal hangup (SIGHUP).  Ctrl-D is intentionally
# NOT handled — it is an EOF on stdin, not a signal, and the daemon never reads
# stdin (under systemd stdin is /dev/null, so tying shutdown to it would exit
# instantly).  Use Ctrl-C or `systemctl stop` instead.
_SHUTDOWN_SIGNALS = tuple(
    s for s in (getattr(signal, n, None) for n in ("SIGINT", "SIGTERM", "SIGHUP"))
    if s is not None
)


def _install_signal_handlers() -> None:
    """Route shutdown signals through KeyboardInterrupt.

    Raising in the handler unwinds whatever the main thread is doing — startup
    (including a blocking smartctl pull) or the serving loop — into main()'s
    single try/finally, so the daemon always tears down its worker threads and
    state DB instead of dying with a traceback (Ctrl-C) or being killed silently
    (systemd stop)."""
    def _handler(signum, _frame):
        raise KeyboardInterrupt(signal.Signals(signum).name)
    for sig in _SHUTDOWN_SIGNALS:
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # not the main thread, or signal unavailable on this platform


def _restore_default_signals() -> None:
    """Reset to default disposition so a second signal during the (bounded)
    shutdown force-terminates instead of corrupting cleanup."""
    for sig in _SHUTDOWN_SIGNALS:
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (ValueError, OSError):
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="SMARTMON-*-MIB AgentX subagent")
    parser.add_argument("--config", "-c", metavar="PATH",
                        default="/etc/snmp/extension/smartmon.yaml",
                        help="path to YAML (or key=value) config file (default: %(default)s)")
    parser.add_argument("--state-dir",    metavar="PATH", default=None,
                        help="directory containing smartd --jsonstate *.json files")
    parser.add_argument("--cache-timeout", type=int, default=None, metavar="SEC",
                        help=f"data refresh / poll interval in seconds (config key: "
                             f"cache_timeout; default: {CACHE_TTL})")
    parser.add_argument("--log-level",    default=None,
                        choices=["DEBUG-AGENTX", "DEBUG", "VERBOSE", "INFO",
                                 "NOTICE", "WARNING", "ERROR"],
                        help="minimum log severity written to stderr / log-file "
                             "(default: WARNING). DEBUG-AGENTX = DEBUG plus raw "
                             "net-snmp AgentX PDU tracing to the log file/stderr")
    parser.add_argument("--log-file",     metavar="PATH", default=None,
                        help="append log output to this file in addition to stderr")
    parser.add_argument("--agentx-socket", default=DEFAULT_AGENTX_SOCKET,
                        help="path to the net-snmp AgentX master socket (default: %(default)s)")
    parser.add_argument("-f", dest="foreground", action="store_true",
                        help="run in foreground (default)")
    parser.add_argument("--collect", action="store_true", default=None,
                        help="pull SMART data directly via smartctl instead of "
                             "reading state_dir JSON files")
    parser.add_argument("--state-db", metavar="PATH", default=None,
                        help="SQLite file persisting change timestamps and "
                             "notification baselines across restarts (default: "
                             "off, or the config file's state_db key)")
    parser.add_argument("--once", action="store_true",
                        help="collect and publish once, then exit")
    parser.add_argument("--version", action="version",
                        version=f"smartmon-snmp-agentx {VERSION}",
                        help="print version and exit")
    args = parser.parse_args()

    cfg = _load_config(args.config)

    # Let config file supply agentx_socket if not on command line
    agentx_socket = args.agentx_socket
    if agentx_socket == DEFAULT_AGENTX_SOCKET and "agentx_socket" in cfg:
        agentx_socket = cfg["agentx_socket"]

    _configure_smartmon(args, cfg)

    LOGGER.info("smartmon AgentX v%s starting: mode=%s source=%s socket=%s "
                "cache_timeout=%ds", VERSION, "collect" if _st.collect else "file",
                "smartctl" if _st.collect else _st.state_dir, agentx_socket, _st.ttl)

    if not _st.collect and not _st.state_dir:
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

    # Route Ctrl-C / SIGTERM / SIGHUP through the single try/finally below so a
    # signal during startup (e.g. a blocking smartctl pull) shuts down cleanly
    # rather than dumping a traceback or being killed mid-cleanup.
    _install_signal_handlers()

    worker = None
    udev_thread = None
    stop_event = threading.Event()
    try:
        agent = agent_cls(
            AgentName="smartmonAgent",
            MasterSocket=agentx_socket,
            UseMIBFiles=False,
        )
        # Enable net-snmp AgentX PDU tracing before registration so the register/
        # start exchange with the master is captured too.
        if _st.agentx_debug:
            _enable_agentx_debug(_st.log_path)

        scalars = _register_scalars(agent)
        tables  = _register_tables(agent)
        _register_custom_handlers()  # custom handlers for custom_handler tables

        agent.start()
        _st.agentx_connected = True   # subagent session to the master is up

        # Open + load persisted state BEFORE the first build so loaded hashes
        # match the current data (timestamps are preserved, not advanced) and
        # notification baselines suppress restart trap storms.
        state_db_path = args.state_db if args.state_db is not None else cfg.get("state_db", "")
        state_db_open(state_db_path)
        state_db_load()

        _refresh_and_publish(agent, scalars, tables)
        # Devices present at startup must not raise device-discovered traps; arm
        # detection only after the first build has seeded all baselines.
        _st.initial_scan_done = True

        # Tell systemd we are up and serving (no-op when not under systemd).
        _sd_notify_status("READY=1")

        if args.once:
            return   # finally closes the state DB

        # Producer/consumer split: the worker thread owns all data collection and
        # _st mutation; the main thread owns all net-snmp socket access (net-snmp
        # is not thread-safe).  The main thread answers SNMP, publishes the
        # snapshots the worker hands it over _publish_q, and sends the trap
        # descriptors the worker enqueues onto _notify_q.  It polls at
        # NOTIFY_POLL_INTERVAL rather than blocking indefinitely so worker-detected
        # traps are delivered promptly even with no client traffic.
        api = _get_trap_api()

        worker = threading.Thread(target=_collector_loop, args=(stop_event,),
                                  name="smartmon-collector", daemon=True)
        worker.start()

        # Collect mode: drive discovery is event-driven via udev rather than a
        # `smartctl --scan` on every poll.  File mode has no devices to hotplug.
        if _st.collect:
            udev_thread = threading.Thread(target=_udev_monitor_loop,
                                           args=(stop_event,),
                                           name="smartmon-udev", daemon=True)
            udev_thread.start()

        # SNMP request-burst tracking for the VERBOSE performance summary.
        walk_active = False
        walk_count  = 0
        walk_start  = 0.0
        walk_last   = 0.0

        # systemd watchdog: ping WATCHDOG=1 every wd_interval seconds (0 = off).
        # The loop already wakes at least every NOTIFY_POLL_INTERVAL, so pings
        # land on time.  prev_conn tracks the agentx connect/disconnect flag so a
        # transition refreshes the STATUS= line.
        wd_interval = _sd_watchdog_interval()
        wd_last     = time.monotonic()
        if wd_interval:
            LOGGER.info("systemd watchdog enabled: ping every %.1fs", wd_interval)
        prev_conn = _st.agentx_connected

        while True:
            # Block on the agent's fds (processing packets as fast as they
            # arrive) but wake at least every NOTIFY_POLL_INTERVAL so the worker's
            # queued traps and snapshots are flushed even with no client traffic.
            active = _agent_wait(api, NOTIFY_POLL_INTERVAL)

            # Process all packets that are now pending.  We deliberately do NOT
            # poke the worker per packet: it polls file mtimes every
            # NOTIFY_POLL_INTERVAL on its own, so a per-GETNEXT _refresh_request
            # would only add GIL contention (it woke the worker on every packet,
            # the bulk of the walk slowdown) with no benefit.
            agent.check_and_process(block=False)

            # Track SNMP activity bursts: log the start, count loop wakeups (socket
            # read-ready events), and summarise once idle for SNMP_IDLE_SUMMARY_SEC.
            # A wakeup is NOT one client request: each AgentX getNext is several
            # socket messages (request + response sync), so wakeups run ~3x the
            # actual PDU count — confirmed via the DEBUG-AGENTX trace. Hence the
            # summary reports "socket wakeups", not requests.
            now = time.monotonic()
            if active:
                if not walk_active:
                    walk_active, walk_start, walk_count = True, now, 0
                    LOGGER.verbose("SNMP activity started")
                walk_count += 1
                walk_last = now
            elif walk_active and now - walk_last >= SNMP_IDLE_SUMMARY_SEC:
                dur  = walk_last - walk_start
                rate = walk_count / dur if dur > 0 else 0.0
                LOGGER.verbose("SNMP activity summary: %d socket wakeups over %.1fs "
                               "(%.0f/s; wakeups run ~3x the AgentX PDU count)",
                               walk_count, dur, rate)
                walk_active = False

            # Drain to the most recent snapshot; publish it on this (main) thread.
            # A snapshot is only queued when the worker actually rebuilt, and that
            # same rebuild is the only thing that queues traps — so trap sending is
            # coupled to a real data refresh and skipped on every other iteration.
            snapshot = None
            while not _publish_q.empty():
                snapshot = _publish_q.get_nowait()
            if snapshot is not None:
                before = time.monotonic()
                _publish(agent, scalars, tables, snapshot)
                _log_published(len(snapshot), time.monotonic() - before)
                # Send the traps detected during that refresh (sole net-snmp caller).
                _drain_and_send_traps()

            # Refresh the systemd STATUS= line whenever the worker completed a
            # poll (disk/OID/updated/error fields), even when nothing was
            # republished — this is what keeps the "updated" timestamp moving.
            if _status_event.is_set():

                _status_event.clear()
                _sd_notify_status()

            # Surface agentx connect/disconnect transitions to systemd.
            if _st.agentx_connected != prev_conn:
                prev_conn = _st.agentx_connected
                LOGGER.info("agentx %s",
                            "connected" if prev_conn else "disconnected")
                _sd_notify_status()

            # Pet the systemd watchdog (no-op when WatchdogSec= is unset).
            if wd_interval and now - wd_last >= wd_interval:
                _sd_notify("WATCHDOG=1")
                wd_last = now
    except KeyboardInterrupt as exc:
        LOGGER.info("received %s — shutting down", str(exc) or "interrupt")
    finally:
        # Reset signal disposition first so a second Ctrl-C / SIGTERM during the
        # bounded shutdown below force-terminates instead of corrupting cleanup.
        _restore_default_signals()
        _sd_notify("STOPPING=1")   # tell systemd we are tearing down
        stop_event.set()
        _refresh_request.set()   # wake the worker so it observes stop promptly
        # The udev thread blocks on udevadm's stdout; terminate it to unblock.
        if _st.udev_proc is not None:
            try:
                _st.udev_proc.terminate()
            except Exception:
                pass
        if worker is not None:
            worker.join(timeout=2.0)
        if udev_thread is not None:
            udev_thread.join(timeout=2.0)
        state_db_close()         # safe: the worker (sole save() caller) has joined


if __name__ == "__main__":
    main()
