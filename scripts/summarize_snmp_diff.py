#!/usr/bin/env python3
"""
summarize_snmp_diff.py

Summarize SNMP diff output by comparing LastChange markers against
the data objects that actually changed.

Supports:

  diff old.snmp new.snmp | ./summarize_snmp_diff.py
  diff -u old.snmp new.snmp | ./summarize_snmp_diff.py
  diff --color=always -u old.snmp new.snmp | ./summarize_snmp_diff.py

Main goal:

  Show whether LastChange changed only because polling happened,
  or because data below that section actually changed.

Useful debug:

  diff -u old.snmp new.snmp | ./summarize_snmp_diff.py --debug
  diff -u old.snmp new.snmp | ./summarize_snmp_diff.py --show-values
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# ANSI/color handling
#
# Some diff commands emit color codes even when piped. Then lines start with
# ESC instead of '-' / '+' / '<' / '>', and normal parsing fails.
# ---------------------------------------------------------------------------

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# SNMP/diff parsing
# ---------------------------------------------------------------------------

SNMP_LINE_RE = re.compile(
    r"^(?P<oid>[A-Z0-9-]+::[^\s=]+)\s+=\s+(?P<value>.+)$"
)


def parse_diff_line(line: str) -> tuple[str, str] | None:
    """
    Return:
      ("old", snmp_line)
      ("new", snmp_line)
      None

    Handles normal diff:
      < old
      > new

    Handles unified diff:
      -old
      +new

    Handles ANSI colored diff by stripping escape codes first.
    """

    line = strip_ansi(line.rstrip("\n"))

    if not line:
        return None

    # Unified diff metadata.
    if line.startswith("--- ") or line.startswith("+++ "):
        return None

    if line.startswith("@@ "):
        return None

    # Context line in unified diff. Not changed data.
    if line.startswith(" "):
        return None

    # Normal diff old/new lines.
    if line.startswith("< "):
        return "old", line[2:]

    if line.startswith("> "):
        return "new", line[2:]

    # Unified diff old/new lines.
    if line.startswith("-"):
        return "old", line[1:]

    if line.startswith("+"):
        return "new", line[1:]

    return None


def parse_diff_text(data: str, debug: bool = False) -> tuple[dict[str, str], dict[str, str]]:
    old: dict[str, str] = {}
    new: dict[str, str] = {}

    total_lines = 0
    diff_candidate_lines = 0
    snmp_matched_lines = 0
    ignored_diff_lines = 0

    for raw_line in data.splitlines():
        total_lines += 1

        parsed = parse_diff_line(raw_line)
        if parsed is None:
            continue

        diff_candidate_lines += 1

        side, snmp_line = parsed

        match = SNMP_LINE_RE.match(snmp_line)
        if not match:
            ignored_diff_lines += 1
            if debug:
                print(
                    f"DEBUG: diff line did not match SNMP regex: {snmp_line!r}",
                    file=sys.stderr,
                )
            continue

        snmp_matched_lines += 1

        oid = match.group("oid")
        value = match.group("value")

        if side == "old":
            old[oid] = value
        else:
            new[oid] = value

    if debug:
        print("DEBUG: parse_diff_text()", file=sys.stderr)
        print(f"DEBUG: total input lines        : {total_lines}", file=sys.stderr)
        print(f"DEBUG: diff candidate lines    : {diff_candidate_lines}", file=sys.stderr)
        print(f"DEBUG: SNMP matched lines      : {snmp_matched_lines}", file=sys.stderr)
        print(f"DEBUG: ignored diff lines      : {ignored_diff_lines}", file=sys.stderr)
        print(f"DEBUG: old OIDs parsed         : {len(old)}", file=sys.stderr)
        print(f"DEBUG: new OIDs parsed         : {len(new)}", file=sys.stderr)

    return old, new


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ChangedObject:
    oid: str
    old: str
    new: str

    @property
    def short_oid(self) -> str:
        if "::" in self.oid:
            return self.oid.split("::", 1)[1]
        return self.oid


@dataclass
class Summary:
    timestamps: list[ChangedObject] = field(default_factory=list)

    lastchange_by_section: dict[str, list[ChangedObject]] = field(default_factory=dict)
    lastchange_by_subindex_group: dict[str, list[ChangedObject]] = field(default_factory=dict)

    data_by_section: dict[str, list[ChangedObject]] = field(default_factory=dict)
    devstat_data_by_group: dict[str, list[ChangedObject]] = field(default_factory=dict)

    unclassified: list[ChangedObject] = field(default_factory=list)
    added_removed: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

DEVSTAT_GROUP_ID_TO_NAME = {
    "1": "generalStatistics",
    "2": "freeFallStatistics",
    "3": "freeFallStatistics",
    "4": "rotatingMediaStatistics",
    "5": "generalErrorsStatistics",
    "6": "temperatureStatistics",
    "255": "vendorSpecific",
}


def is_timestamp_oid(oid: str) -> bool:
    return any(
        marker in oid
        for marker in (
            "::smartmonDeviceLastPollTime.",
            "::smartmonSensorValueTimestamp.",
        )
    )


def get_device_lastchange_section(oid: str) -> str | None:
    match = re.match(
        r"^SMARTMON-SATA-MIB::smartSATAChangeByDeviceLastChange\."
        r"\d+\.([A-Za-z0-9_]+)$",
        oid,
    )
    if match:
        return match.group(1)

    return None


def get_subindex_lastchange_group(oid: str) -> tuple[str, str] | None:
    match = re.match(
        r"^SMARTMON-SATA-MIB::smartSATAChangeBySubindexLastChange\."
        r"\d+\.([A-Za-z0-9_]+)\.(\d+)\.(\d+)$",
        oid,
    )

    if not match:
        return None

    section = match.group(1)
    group_id = match.group(2)
    group_name = DEVSTAT_GROUP_ID_TO_NAME.get(group_id, f"group_{group_id}")

    return section, group_name


def infer_data_section(oid: str) -> str | None:
    short = oid.split("::", 1)[1] if "::" in oid else oid

    if short.startswith("smartmonSataPowerOnHours."):
        return "sataAttr"

    if short.startswith("smartmonSataAttr"):
        return "sataAttr"

    if short.startswith("smartmonSataDevStatValue."):
        return "sataDevStat"

    if short.startswith("smartmonSensorValue.") and not short.startswith(
        "smartmonSensorValueTimestamp."
    ):
        return "sensor"

    return None


def infer_devstat_group(oid: str) -> str | None:
    match = re.match(
        r"^SMARTMON-SATA-MIB::smartmonSataDevStatValue\."
        r"\d+\.([A-Za-z0-9_]+)\.\d+$",
        oid,
    )

    if match:
        return match.group(1)

    return None


def compact_data_name(obj: ChangedObject) -> str:
    short = obj.short_oid

    match = re.match(
        r"smartmonSataDevStatValue\.\d+\.([A-Za-z0-9_]+)\.(\d+)$",
        short,
    )
    if match:
        return f"{match.group(1)}.{match.group(2)}"

    match = re.match(
        r"smartmonSataAttr([A-Za-z0-9_]+)\.\d+\.(\d+)$",
        short,
    )
    if match:
        return f"smartmonSataAttr{match.group(1)}.{match.group(2)}"

    match = re.match(
        r"smartmonSataPowerOnHours\.\d+$",
        short,
    )
    if match:
        return "smartmonSataPowerOnHours"

    return short


def group_sort_key(name: str) -> tuple[int, str]:
    for group_id, group_name in DEVSTAT_GROUP_ID_TO_NAME.items():
        if name == group_name:
            return int(group_id), name

    match = re.match(r"group_(\d+)$", name)
    if match:
        return int(match.group(1)), name

    return 999999, name


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def build_summary(old: dict[str, str], new: dict[str, str]) -> Summary:
    summary = Summary()

    all_old = set(old)
    all_new = set(new)

    changed_oids = sorted(all_old & all_new)
    summary.added_removed = sorted(all_old ^ all_new)

    for oid in changed_oids:
        if old[oid] == new[oid]:
            continue

        obj = ChangedObject(oid=oid, old=old[oid], new=new[oid])

        if is_timestamp_oid(oid):
            summary.timestamps.append(obj)
            continue

        section = get_device_lastchange_section(oid)
        if section is not None:
            summary.lastchange_by_section.setdefault(section, []).append(obj)
            continue

        subindex = get_subindex_lastchange_group(oid)
        if subindex is not None:
            section_name, group_name = subindex
            key = f"{section_name} {group_name}"
            summary.lastchange_by_subindex_group.setdefault(key, []).append(obj)
            continue

        data_section = infer_data_section(oid)
        if data_section is not None:
            summary.data_by_section.setdefault(data_section, []).append(obj)

            devstat_group = infer_devstat_group(oid)
            if devstat_group is not None:
                summary.devstat_data_by_group.setdefault(devstat_group, []).append(obj)

            continue

        summary.unclassified.append(obj)

    return summary


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_list(items: list[str], indent: str = "  ") -> None:
    if not items:
        print(f"{indent}None")
        return

    for item in items:
        print(f"{indent}{item}")


def print_changed_objects(objects: list[ChangedObject], show_values: bool) -> None:
    if not objects:
        print("    None")
        return

    for obj in sorted(objects, key=compact_data_name):
        print(f"    {compact_data_name(obj)}")

        if show_values:
            print(f"      {obj.old}")
            print(f"   -> {obj.new}")


def render(summary: Summary, show_values: bool, debug: bool, no_suspicion: bool) -> None:
    lastchange_sections = set(summary.lastchange_by_section)
    data_sections = set(summary.data_by_section)

    lastchange_with_data = sorted(lastchange_sections & data_sections)
    lastchange_without_data = sorted(lastchange_sections - data_sections)

    subindex_without_data: list[str] = []
    subindex_with_data: list[str] = []

    devstat_groups_with_data = set(summary.devstat_data_by_group)

    for key in sorted(
        summary.lastchange_by_subindex_group,
        key=lambda x: group_sort_key(x.split(" ", 1)[1] if " " in x else x),
    ):
        parts = key.split(" ", 1)
        group_name = parts[1] if len(parts) == 2 else key

        if group_name in devstat_groups_with_data:
            subindex_with_data.append(key)
        else:
            subindex_without_data.append(key)

    print("Brief summary sorted by belonging")
    print("=" * 80)
    print()

    print("Poll/timestamp-only changes")
    print("-" * 80)
    print_list(sorted(obj.short_oid for obj in summary.timestamps))
    print()

    print("LastChange changed, but no actual data change shown in diff")
    print("-" * 80)

    no_data_items: list[str] = []
    no_data_items.extend(lastchange_without_data)
    no_data_items.extend(subindex_without_data)

    print_list(no_data_items)
    print()

    print("LastChange changed, and actual data changed")
    print("-" * 80)

    printed = False

    for section in lastchange_with_data:
        printed = True
        print(f"  {section}")
        print_changed_objects(summary.data_by_section.get(section, []), show_values)
        print()

    for key in subindex_with_data:
        printed = True
        print(f"  {key}")
        _, group_name = key.split(" ", 1)
        print_changed_objects(summary.devstat_data_by_group.get(group_name, []), show_values)
        print()

    orphan_data_sections = sorted(data_sections - lastchange_sections)
    for section in orphan_data_sections:
        printed = True
        print(f"  {section}")
        print_changed_objects(summary.data_by_section.get(section, []), show_values)
        print()

    if not printed:
        print("  None")
        print()

    if not no_suspicion:
        print("Suspicion from diff")
        print("-" * 80)

        suspicious = no_data_items

        if suspicious:
            print(
                "  LastChange appears to be updated more broadly than the actual data changes suggest."
            )
            print(
                "  These sections/groups received a new LastChange without matching changed data in the diff:"
            )

            for item in suspicious:
                print(f"    {item}")
        else:
            print("  No obvious over-broad LastChange update detected.")

        print()

    if summary.added_removed:
        print("Added or removed OIDs")
        print("-" * 80)
        print_list(summary.added_removed)
        print()

    if debug and summary.unclassified:
        print("Unclassified changed OIDs")
        print("-" * 80)
        for obj in summary.unclassified:
            print(f"  {obj.short_oid}")
            if show_values:
                print(f"    {obj.old}")
                print(f" -> {obj.new}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize SNMP diff output by LastChange/data belonging."
    )

    parser.add_argument(
        "--show-values",
        action="store_true",
        help="Show old/new values for changed data objects.",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show parser/debug information on stderr and unclassified OIDs in output.",
    )

    parser.add_argument(
        "--no-suspicion",
        action="store_true",
        help="Do not print the suspicion section.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.debug:
        print(f"DEBUG: stdin isatty            : {sys.stdin.isatty()}", file=sys.stderr)

    data = sys.stdin.read()

    if args.debug:
        print(
            f"DEBUG: bytes read from stdin   : {len(data.encode(errors='replace'))}",
            file=sys.stderr,
        )
        print(f"DEBUG: chars read from stdin   : {len(data)}", file=sys.stderr)

        preview = data.splitlines()[:20]
        print("DEBUG: first input lines:", file=sys.stderr)

        if preview:
            for i, line in enumerate(preview, 1):
                print(f"DEBUG:   {i:02d} raw  : {line!r}", file=sys.stderr)
                print(f"DEBUG:   {i:02d} clean: {strip_ansi(line)!r}", file=sys.stderr)
        else:
            print("DEBUG:   <no input>", file=sys.stderr)

    if not data:
        print("No input received on stdin.", file=sys.stderr)
        print("Try:", file=sys.stderr)
        print("  diff old.snmp new.snmp | python3 summarize_snmp_diff.py --debug", file=sys.stderr)
        print("  diff -u old.snmp new.snmp | python3 summarize_snmp_diff.py --debug", file=sys.stderr)
        return 2

    old, new = parse_diff_text(data, debug=args.debug)

    if not old and not new:
        print("No SNMP diff lines found on stdin.", file=sys.stderr)
        print("Debug hint:", file=sys.stderr)
        print("  Run with --debug and check whether clean input lines start with '< ', '> ', '+', or '-'.", file=sys.stderr)
        print("  Also check whether SNMP lines contain 'MIB::object = value'.", file=sys.stderr)
        return 2

    summary = build_summary(old, new)

    render(
        summary,
        show_values=args.show_values,
        debug=args.debug,
        no_suspicion=args.no_suspicion,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
