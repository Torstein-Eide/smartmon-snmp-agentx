#!/usr/bin/env python3
"""
Pretty-print raw SNMP trap logs.

Features:
  - Filters away non-trap noise from snmptrapd/snmptranslate
  - Resolves OIDs with snmptranslate
  - Compact view by default
  - Hides numeric OID by default
  - Can show full long view when needed

Examples:
  ./snmp-trap-pretty.py traps.log

  ./snmp-trap-pretty.py traps.log -o traps.pretty.txt

  ./snmp-trap-pretty.py traps.log --show-oid

  ./snmp-trap-pretty.py traps.log --format long --show-oid

  ./snmp-trap-pretty.py traps.log \
    --mibs ALL \
    --mibdirs "/usr/local/share/snmp/mibs:/var/lib/mibs/iana:/var/lib/mibs/ietf:./doc"
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable


DEFAULT_MIBDIRS = "/usr/local/share/snmp/mibs:/var/lib/mibs/iana:/var/lib/mibs/ietf:./doc"


HEADER_RE = re.compile(
    r"""
    ^
    (?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})
    \s+
    (?P<host>\S+)
    \s+
    \[(?P<transport>.+?)\]:
    \s*$
    """,
    re.VERBOSE,
)

VARBIND_START_RE = re.compile(
    r"(?=(?:^|\t|\s{2,})(\.\d+(?:\.\d+)+)\s+=\s+)"
)

VARBIND_RE = re.compile(
    r"""
    ^
    (?P<oid>\.\d+(?:\.\d+)+)
    \s*=\s*
    (?P<type>[A-Za-z][A-Za-z0-9_-]*)
    :
    \s*
    (?P<value>.*)
    $
    """,
    re.VERBOSE,
)

NUMERIC_OID_RE = re.compile(r"^\.\d+(?:\.\d+)+$")


NOISE_PATTERNS = [
    re.compile(r"^MIB search path:", re.IGNORECASE),
    re.compile(r"^Cannot find module ", re.IGNORECASE),
    re.compile(r"^Did not find ", re.IGNORECASE),
    re.compile(r"^Bad operator ", re.IGNORECASE),
    re.compile(r"^NET-SNMP version .*", re.IGNORECASE),
    re.compile(r"^Stopping snmptrapd", re.IGNORECASE),
    re.compile(r"^read_config_store open failure ", re.IGNORECASE),
    re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} NET-SNMP version .*", re.IGNORECASE),
]


@dataclass
class Varbind:
    raw: str
    oid: str | None
    name: str | None
    value_type: str | None
    value: str | None
    value_name: str | None


@dataclass
class Trap:
    timestamp: str | None
    host: str | None
    transport: str | None
    varbinds: list[str]


class OidResolver:
    def __init__(
        self,
        enabled: bool = True,
        mibs: str | None = "ALL",
        mibdirs: str | None = DEFAULT_MIBDIRS,
        timeout: float = 2.0,
    ) -> None:
        self.enabled = enabled
        self.mibs = mibs
        self.mibdirs = mibdirs
        self.timeout = timeout
        self.snmptranslate = shutil.which("snmptranslate")

        if not self.snmptranslate:
            self.enabled = False

    @lru_cache(maxsize=8192)
    def resolve(self, oid: str) -> str | None:
        if not self.enabled:
            return None

        if not NUMERIC_OID_RE.match(oid):
            return None

        env = os.environ.copy()

        if self.mibs:
            env["MIBS"] = self.mibs

        if self.mibdirs:
            env["MIBDIRS"] = self.mibdirs

        cmd = [self.snmptranslate]

        if self.mibs:
            cmd += ["-m", self.mibs]

        if self.mibdirs:
            cmd += ["-M", self.mibdirs]

        cmd.append(oid)

        try:
            result = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except Exception:
            return None

        if result.returncode != 0:
            return None

        resolved = result.stdout.strip()

        if not resolved:
            return None

        if resolved == oid:
            return None

        return resolved


def is_noise_line(line: str) -> bool:
    stripped = line.strip()

    if not stripped:
        return True

    for pattern in NOISE_PATTERNS:
        if pattern.search(stripped):
            return True

    return False


def line_has_varbind(line: str) -> bool:
    return bool(VARBIND_START_RE.search(line))


def split_varbinds(text: str) -> list[str]:
    text = text.strip()

    if not text:
        return []

    matches = list(VARBIND_START_RE.finditer(text))

    if not matches:
        return []

    parts: list[str] = []

    for i, match in enumerate(matches):
        start = match.start(1)
        end = matches[i + 1].start(1) if i + 1 < len(matches) else len(text)
        part = text[start:end].strip(" \t")

        if part:
            parts.append(part)

    return parts


def parse_traps(lines: Iterable[str], keep_raw: bool = False) -> list[Trap]:
    traps: list[Trap] = []
    current: Trap | None = None

    for raw_line in lines:
        line = raw_line.rstrip("\n")

        if not line.strip():
            continue

        header = HEADER_RE.match(line)

        if header:
            if current is not None and current.varbinds:
                traps.append(current)

            current = Trap(
                timestamp=header.group("timestamp"),
                host=header.group("host"),
                transport=header.group("transport"),
                varbinds=[],
            )
            continue

        if is_noise_line(line):
            if keep_raw and current is not None:
                current.varbinds.append(f"RAW: {line.strip()}")
            continue

        if not line_has_varbind(line):
            if keep_raw and current is not None:
                current.varbinds.append(f"RAW: {line.strip()}")
            continue

        if current is None:
            current = Trap(
                timestamp=None,
                host=None,
                transport=None,
                varbinds=[],
            )

        current.varbinds.extend(split_varbinds(line))

    if current is not None and current.varbinds:
        traps.append(current)

    return traps


def resolve_varbind(varbind: str, resolver: OidResolver) -> Varbind:
    if varbind.startswith("RAW: "):
        return Varbind(
            raw=varbind,
            oid=None,
            name=None,
            value_type=None,
            value=varbind[5:],
            value_name=None,
        )

    parsed = VARBIND_RE.match(varbind)

    if not parsed:
        return Varbind(
            raw=varbind,
            oid=None,
            name=None,
            value_type=None,
            value=varbind,
            value_name=None,
        )

    oid = parsed.group("oid")
    value_type = parsed.group("type")
    value = parsed.group("value")

    name = resolver.resolve(oid)
    value_name = resolver.resolve(value) if value_type == "OID" else None

    return Varbind(
        raw=varbind,
        oid=oid,
        name=name,
        value_type=value_type,
        value=value,
        value_name=value_name,
    )


def short_name(name: str | None, oid: str | None, show_oid: bool) -> str:
    if name:
        if show_oid and oid:
            return f"{name} [{oid}]"
        return name

    if oid:
        return oid

    return "<raw>"


def format_value(vb: Varbind, show_oid: bool) -> str:
    if vb.value is None:
        return ""

    if vb.value_type == "OID" and vb.value_name:
        if show_oid:
            return f"{vb.value_name} [{vb.value}]"
        return vb.value_name

    return vb.value


def find_trap_oid(trap: Trap, resolver: OidResolver) -> Varbind | None:
    for raw in trap.varbinds:
        vb = resolve_varbind(raw, resolver)

        if vb.oid == ".1.3.6.1.6.3.1.1.4.1.0":
            return vb

    return None


def extract_device_summary(varbinds: list[Varbind]) -> str | None:
    device_name = None
    device_path = None
    sensor_name = None
    sensor_value = None
    sensor_limit = None
    sensor_units = None

    for vb in varbinds:
        name = vb.name or ""

        if name.endswith("smartmonDeviceName") or "smartmonDeviceName." in name:
            device_name = vb.value

        elif name.endswith("smartmonDevicePath") or "smartmonDevicePath." in name:
            device_path = vb.value

        elif name.endswith("smartmonSensorName") or "smartmonSensorName." in name:
            sensor_name = vb.value

        elif name.endswith("smartmonSensorValue") or "smartmonSensorValue." in name:
            sensor_value = vb.value

        elif (
            "smartmonSensorHighCritical" in name
            or "smartmonSensorHighWarning" in name
            or "smartmonSensorLowWarning" in name
            or "smartmonSensorLowCritical" in name
        ):
            sensor_limit = vb.value

        elif name.endswith("smartmonSensorUnitsDisplay") or "smartmonSensorUnitsDisplay." in name:
            sensor_units = vb.value

    parts = []

    if device_name:
        parts.append(str(device_name))

    if device_path:
        parts.append(f"({device_path})")

    if sensor_name and sensor_value:
        unit = f" {sensor_units}" if sensor_units else ""
        if sensor_limit:
            parts.append(f"{sensor_name}: {sensor_value}{unit}, limit {sensor_limit}{unit}")
        else:
            parts.append(f"{sensor_name}: {sensor_value}{unit}")

    if parts:
        return " ".join(parts)

    return None


def format_compact_trap(
    trap: Trap,
    number: int,
    resolver: OidResolver,
    show_oid: bool,
) -> str:
    resolved = [resolve_varbind(raw, resolver) for raw in trap.varbinds]
    trap_oid_vb = find_trap_oid(trap, resolver)

    trap_name = "<unknown trap>"

    if trap_oid_vb and trap_oid_vb.value_type == "OID":
        if trap_oid_vb.value_name:
            trap_name = trap_oid_vb.value_name
            if show_oid:
                trap_name += f" [{trap_oid_vb.value}]"
        elif trap_oid_vb.value:
            trap_name = trap_oid_vb.value

    time = trap.timestamp or "<missing time>"
    host = trap.host or "<missing host>"

    out: list[str] = []

    out.append(f"#{number:02} {time} {host}")
    out.append(f"Trap: {trap_name}")

    summary = extract_device_summary(resolved)
    if summary:
        out.append(f"Info: {summary}")

    for vb in resolved:
        # Skip sysUpTime and snmpTrapOID in compact details.
        if vb.oid in {
            ".1.3.6.1.2.1.1.3.0",
            ".1.3.6.1.6.3.1.1.4.1.0",
        }:
            continue

        name = short_name(vb.name, vb.oid, show_oid)
        value = format_value(vb, show_oid)

        if vb.value_type:
            out.append(f"  - {name}: {value}")
        else:
            out.append(f"  - RAW: {value}")

    return "\n".join(out)


def format_long_trap(
    trap: Trap,
    number: int,
    width: int,
    resolver: OidResolver,
    show_oid: bool,
) -> str:
    sep = "=" * width
    small_sep = "-" * width

    out: list[str] = []

    out.append(sep)
    out.append(f"TRAP #{number}")
    out.append(small_sep)

    out.append(f"Time      : {trap.timestamp or '<missing>'}")
    out.append(f"Host      : {trap.host or '<missing>'}")
    out.append(f"Transport : {trap.transport or '<missing>'}")

    trap_oid_vb = find_trap_oid(trap, resolver)

    if trap_oid_vb and trap_oid_vb.value:
        out.append(f"Trap OID  : {format_value(trap_oid_vb, show_oid=True)}")

    out.append(small_sep)
    out.append("Varbinds:")

    for i, raw in enumerate(trap.varbinds, start=1):
        vb = resolve_varbind(raw, resolver)

        if vb.oid:
            name = short_name(vb.name, vb.oid, show_oid)
            value = format_value(vb, show_oid)
            out.append(f"  [{i:02}] {name}")
            out.append(f"       type : {vb.value_type}")
            out.append(f"       value: {value}")
        else:
            out.append(f"  [{i:02}] RAW")
            out.append(f"       {vb.value}")

    out.append("")

    return "\n".join(out)


def read_input(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    return sys.stdin.read()


def write_output(path: str | None, output: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)

            if output and not output.endswith("\n"):
                f.write("\n")
    else:
        print(output)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert raw SNMP trap logs into readable grouped output."
    )

    parser.add_argument(
        "file",
        nargs="?",
        help="Input file. If omitted, reads from stdin.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Write output to file instead of stdout.",
    )

    parser.add_argument(
        "--format",
        choices=["compact", "long"],
        default="compact",
        help="Output format. Default: compact.",
    )

    parser.add_argument(
        "--show-oid",
        action="store_true",
        help="Show numeric OIDs next to resolved MIB names.",
    )

    parser.add_argument(
        "--verbose-raw",
        action="store_true",
        help="Keep non-trap/raw lines instead of filtering them away.",
    )

    parser.add_argument(
        "--width",
        type=int,
        default=100,
        help="Separator width for long format. Default: 100.",
    )

    parser.add_argument(
        "--mibs",
        default="ALL",
        help="MIB list passed to snmptranslate. Default: ALL.",
    )

    parser.add_argument(
        "--mibdirs",
        default=DEFAULT_MIBDIRS,
        help=(
            "Colon-separated MIB search paths. "
            f"Default: {DEFAULT_MIBDIRS}"
        ),
    )

    parser.add_argument(
        "--no-mib-lookup",
        action="store_true",
        help="Disable snmptranslate/MIB lookup.",
    )

    parser.add_argument(
        "--snmptranslate-timeout",
        type=float,
        default=2.0,
        help="Timeout per snmptranslate lookup in seconds. Default: 2.0.",
    )

    args = parser.parse_args()

    resolver = OidResolver(
        enabled=not args.no_mib_lookup,
        mibs=args.mibs,
        mibdirs=args.mibdirs,
        timeout=args.snmptranslate_timeout,
    )

    data = read_input(args.file)

    traps = parse_traps(
        data.splitlines(),
        keep_raw=args.verbose_raw,
    )

    if args.format == "compact":
        output = "\n\n".join(
            format_compact_trap(
                trap=trap,
                number=i,
                resolver=resolver,
                show_oid=args.show_oid,
            )
            for i, trap in enumerate(traps, start=1)
        )
    else:
        output = "\n".join(
            format_long_trap(
                trap=trap,
                number=i,
                width=args.width,
                resolver=resolver,
                show_oid=args.show_oid,
            )
            for i, trap in enumerate(traps, start=1)
        )

    write_output(args.output, output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
