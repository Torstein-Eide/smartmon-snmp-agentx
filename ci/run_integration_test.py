#!/usr/bin/env python3
"""ci/run_integration_test.py - live SNMP integration test for smartmon-snmp-agentxd."""

import argparse
import fnmatch
import glob
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import yaml

SNMP_STABLE_OUTPUT_ARGS = ["-OenU", "-Ih"]

# ---------------------------------------------------------------------------
# Colour helpers (disabled when not a tty or NOCOLOR is set)
# ---------------------------------------------------------------------------
_COLOUR = sys.stdout.isatty() and not os.environ.get("NOCOLOR")

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

def _green(t):  return _c("92", t)
def _yellow(t): return _c("93", t)
def _red(t):    return _c("91", t)
def _bold(t):   return _c("1",  t)
def _dim(t):    return _c("2",  t)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f)
    for key in ("config", "fixture_variants", "discovery", "walks", "sections"):
        if key not in cfg:
            die(f"YAML missing required top-level key: {key}")
    return cfg


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

def find_binary(cfg: dict, repo_root: Path, override: Optional[str]) -> str:
    if override:
        if not os.access(override, os.X_OK):
            die(f"--binary is not executable: {override}")
        return override
    env_val = os.environ.get("AGENTXD_BIN", "")
    if env_val:
        if not os.access(env_val, os.X_OK):
            die(f"AGENTXD_BIN is not executable: {env_val}")
        return env_val
    for rel in cfg["config"].get("binary_search_paths", []):
        candidate = repo_root / rel if not Path(rel).is_absolute() else Path(rel)
        if candidate.exists() and os.access(str(candidate), os.X_OK):
            return str(candidate)
    die("binary not found; set AGENTXD_BIN, use --binary, or build first")


def require_cmd(name: str) -> None:
    if not shutil.which(name):
        die(f"required command not found: {name}")


def build_snmp_env(repo_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    mib_dirs = [Path("/var/lib/mibs/iana"), Path("/var/lib/mibs/ietf"), repo_root / "doc"]
    existing = env.get("MIBDIRS", "")
    available = [str(p) for p in mib_dirs if p.is_dir()]
    if available:
        if existing:
            env["MIBDIRS"] = ":".join([existing, *available])
        else:
            # Leading '+' keeps Net-SNMP's built-in default MIB search path.
            env["MIBDIRS"] = "+" + ":".join(available)
    env["MIBS"] = "ALL"
    return env


# ---------------------------------------------------------------------------
# Error / exit
# ---------------------------------------------------------------------------

def die(msg: str) -> None:
    print(_red(f"ERROR: {msg}"), file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Fixture sorting
# ---------------------------------------------------------------------------

def setup_fixtures(src_dir: str, run_dir: Path, patterns: list[str]) -> tuple[Path, Path]:
    live = run_dir / "fixtures"
    variants = run_dir / "fixture-variants"
    live.mkdir()
    variants.mkdir()
    for fpath in sorted(Path(src_dir).glob("*.json")):
        name = fpath.name
        dest = variants if any(fnmatch.fnmatch(name, p) for p in patterns) else live
        shutil.copy2(fpath, dest / name)
    return live, variants


# ---------------------------------------------------------------------------
# Daemon management
# ---------------------------------------------------------------------------

class DaemonSet:
    def __init__(self):
        self.pids: list[int] = []

    def start(self, *args, stdout=None, stderr=None, env=None) -> int:
        proc = subprocess.Popen(list(args), stdout=stdout, stderr=stderr, env=env)
        self.pids.append(proc.pid)
        return proc.pid

    def stop_all(self) -> None:
        for pid in self.pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        self.pids.clear()


def start_snmptrapd(run_dir: Path, trap_port: int, trap_log: Path,
                    daemons: DaemonSet, snmp_env: dict[str, str]) -> Optional[int]:
    if not shutil.which("snmptrapd"):
        return None
    conf = run_dir / "snmptrapd.conf"
    conf.write_text("disableAuthorization yes\n")
    pid = daemons.start(
        "snmptrapd", "-f", "-Lo", *SNMP_STABLE_OUTPUT_ARGS, "-C", "-c", str(conf),
        f"udp:127.0.0.1:{trap_port}",
        stdout=open(trap_log, "w"), stderr=subprocess.STDOUT,
        env=snmp_env,
    )
    return pid


def start_snmpd(run_dir: Path, socket_path: Path, snmp_port: int,
                trap_port: int, community: str, snmpd_log: Path,
                daemons: DaemonSet, snmp_env: dict[str, str]) -> int:
    conf = run_dir / "snmpd.conf"
    conf.write_text(
        f"master agentx\n"
        f"agentxsocket {socket_path}\n"
        f"rocommunity {community} 127.0.0.1\n"
        f"agentAddress udp:127.0.0.1:{snmp_port}\n"
        f"trap2sink 127.0.0.1:{trap_port} {community}\n"
    )
    extra = os.environ.get("SNMPD_EXTRA_ARGS", "").split()
    pid = daemons.start(
        "snmpd", "-f", "-C", "-c", str(conf), "-Lo", *extra,
        stdout=open(snmpd_log, "w"), stderr=subprocess.STDOUT,
        env=snmp_env,
    )
    # Wait for AgentX socket
    for _ in range(20):
        if socket_path.exists():
            break
        time.sleep(0.5)
    else:
        print(_red("--- snmpd.log ---"), file=sys.stderr)
        print(snmpd_log.read_text(), file=sys.stderr)
        die("snmpd AgentX socket did not appear")
    return pid


def start_agentxd(binary: str, run_dir: Path, socket_path: Path,
                  live_fixtures: Path, agentxd_log: Path,
                  daemons: DaemonSet) -> int:
    conf = run_dir / "agentxd.conf"
    conf.write_text(f"state_dir     {live_fixtures}\nagentx_socket {socket_path}\n")
    extra = os.environ.get("AGENTXD_EXTRA_ARGS", "").split()
    pid = daemons.start(
        binary, "-f", "-c", str(conf), *extra,
        stdout=open(agentxd_log, "w"), stderr=subprocess.STDOUT,
    )
    return pid


def wait_for_registration(snmp_port: int, ent_oid: str, community: str,
                           attempts: int, interval: float,
                           register_log: Path, snmp_env: dict[str, str],
                           agentxd_log: Path, snmpd_log: Path) -> None:
    with open(register_log, "w") as rlog:
        for i in range(1, attempts + 1):
            rlog.write(f"--- attempt {i} ---\n")
            result = subprocess.run(
                ["snmpget", "-v2c", "-c", community, *SNMP_STABLE_OUTPUT_ARGS,
                 f"127.0.0.1:{snmp_port}", f"{ent_oid}.2.1.1.0"],
                capture_output=True, text=True, env=snmp_env,
            )
            out = result.stdout + result.stderr
            rlog.write(out + "\n")
            if "Gauge32:" in out:
                return
            time.sleep(interval)

    print(_red("--- register-poll.log ---"), file=sys.stderr)
    print(register_log.read_text(), file=sys.stderr)
    for label, log in (("snmpd", snmpd_log), ("agentxd", agentxd_log)):
        if log.stat().st_size:
            print(_red(f"--- {label}.log ---"), file=sys.stderr)
            print(log.read_text(), file=sys.stderr)
    die("timed out waiting for agent registration")


# ---------------------------------------------------------------------------
# Walks
# ---------------------------------------------------------------------------

def run_walks(ent_oid: str, snmp_port: int, community: str,
              walk_defs: dict, output_dir: Path,
              snmp_env: dict[str, str]) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for label, suffix in walk_defs.items():
        oid = f"{ent_oid}{suffix}"
        outfile = output_dir / f"snmpwalk-{label}.txt"
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, *SNMP_STABLE_OUTPUT_ARGS,
             f"127.0.0.1:{snmp_port}", oid],
            capture_output=True, text=True, env=snmp_env,
        )
        outfile.write_text(result.stdout + result.stderr)
        files[label] = outfile
    return files


# ---------------------------------------------------------------------------
# Device index discovery
# ---------------------------------------------------------------------------

def discover_index(walk_file: Path, oid_grep_re: str, value_pattern: str,
                   ent_oid: str) -> Optional[str]:
    if not walk_file.exists():
        return None
    ent_esc = re.escape(ent_oid)
    # Match the OID suffix portion after ent_oid; capture it as group 1.
    oid_re = re.compile(rf"^\.?{ent_esc}({oid_grep_re})\s*=")
    for line in walk_file.read_text().splitlines():
        # Fast path: skip lines that don't contain the expected value string.
        if value_pattern not in line:
            continue
        m = oid_re.match(line)
        if m:
            suffix = m.group(1)   # e.g. .3.1.15.1.15.6.1
            parts = [p for p in suffix.split(".") if p]
            if len(parts) >= 2:
                return parts[-2]   # second-to-last component
    return None


def discover_all(cfg: dict, walk_files: dict[str, Path], ent_oid: str) -> dict[str, str]:
    indices: dict[str, str] = {}
    for dev_key, dev in cfg["discovery"].items():
        wfile = walk_files.get(dev["walk_label"])
        if wfile is None:
            die(f"discovery: walk '{dev['walk_label']}' not found for device '{dev_key}'")
        idx = discover_index(wfile, dev["oid_grep_re"], dev["value_pattern"], ent_oid)
        if idx is None or not idx.isdigit():
            die(
                f"could not discover device index for '{dev_key}' "
                f"({dev['label']})\n"
                f"  grep_re: {dev['oid_grep_re']}\n"
                f"  value  : {dev['value_pattern']}\n"
                f"  walk   : {wfile}"
            )
        indices[dev_key] = idx
    return indices


# ---------------------------------------------------------------------------
# Test execution
# ---------------------------------------------------------------------------

def substitute_oid(oid_template: str, device_idx: Optional[str],
                   all_indices: dict[str, str]) -> str:
    result = oid_template
    if device_idx is not None:
        result = result.replace("{D}", device_idx)
    for key, idx in all_indices.items():
        result = result.replace(f"{{{key}}}", idx)
    return result


def check_oid(ent_oid: str, walk_file: Path, oid_suffix: str, expected_re: str
              ) -> tuple[bool, Optional[str]]:
    """Return (matched, actual_line_or_None)."""
    ent_esc = re.escape(ent_oid)
    suffix_esc = re.escape(oid_suffix)
    pattern = re.compile(rf"^\.?{ent_esc}{suffix_esc}\s*=\s*{expected_re}$")
    for line in walk_file.read_text().splitlines():
        if pattern.match(line):
            return True, line
    # Return the actual line for that OID even if value didn't match
    oid_pat = re.compile(rf"^\.?{ent_esc}{suffix_esc}\s*=\s*")
    for line in walk_file.read_text().splitlines():
        if oid_pat.match(line):
            return False, line
    return False, None


def check_rows(ent_oid: str, walk_file: Path, oid_regex: str, minimum: int
               ) -> tuple[bool, int]:
    ent_esc = re.escape(ent_oid)
    pattern = re.compile(rf"^\.?{ent_esc}{oid_regex}")
    count = sum(1 for line in walk_file.read_text().splitlines() if pattern.match(line))
    return count >= minimum, count


def extract_oid_value(walk_file: Path, ent_oid: str, oid_suffix: str) -> Optional[str]:
    """Return the raw value string for an exact OID from a walk file, or None."""
    ent_esc = re.escape(ent_oid)
    suffix_esc = re.escape(oid_suffix)
    pattern = re.compile(rf"^\.?{ent_esc}{suffix_esc}\s*=\s*(.+)$")
    for line in walk_file.read_text().splitlines():
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return None


def _set_json_path(data, path: str, value) -> None:
    """Set a nested value using a dot-separated path; integer segments index lists."""
    keys = path.split(".")
    for k in keys[:-1]:
        data = data[int(k)] if isinstance(data, list) else data[k]
    last = keys[-1]
    if isinstance(data, list):
        data[int(last)] = value
    else:
        data[last] = value


def run_stability_check(check: dict, live_fixtures: Path,
                        ent_oid: str, all_indices: dict[str, str],
                        snmp_port: int, community: str,
                        walk_defs: dict, output_dir: Path,
                        snmp_env: dict[str, str],
                        walk_files: dict[str, Path],
                        verbose: bool) -> tuple[int, int, int, int, list[str]]:
    """Apply JSON mutations to a fixture one by one.  For each mutation verify
    that exactly the expected LastChange OID advances and all others stay stable.

    Returns (mut_passed, mut_failed, oid_passed, oid_failed, failures).

    Symbol key (printed per mutation):
      green !  — expected OID changed as required
      dim   .  — OID stayed stable as required
      red   !  — unexpected change (bug)
      red   .  — expected change missing (bug)
      dim   ?  — OID absent from initial walk (skipped)
    """
    mut_passed = mut_failed = oid_passed = oid_failed = 0
    failures: list[str] = []

    fixture_name = check["fixture"]
    wait_sec = float(check.get("wait_seconds", 2.0))
    walk_label = check["walk"]
    raw_oids = check.get("last_change_oids", [])
    mutations = check.get("mutations", [])

    resolved = [substitute_oid(oid, None, all_indices) for oid in raw_oids]

    initial_walk = walk_files.get(walk_label)
    if initial_walk is None:
        failures.append(f"FAIL: walk '{walk_label}' not in walk_files")
        return 0, 1, 0, 0, failures

    fixture_path = live_fixtures / fixture_name
    if not fixture_path.exists():
        failures.append(f"FAIL: fixture not found: {fixture_path}")
        return 0, 1, 0, 0, failures

    original_bytes = fixture_path.read_bytes()
    before = {oid: extract_oid_value(initial_walk, ent_oid, oid) for oid in resolved}
    safe_check = re.sub(r"[^a-zA-Z0-9_-]", "_", check.get("name", "stability"))

    try:
        for mut_idx, mut in enumerate(mutations):
            label = mut.get("label", f"mutation {mut_idx + 1}")
            expected_oid = substitute_oid(mut["expected_change_oid"], None, all_indices)

            data = json.loads(fixture_path.read_bytes())
            _set_json_path(data, mut["json_path"], mut["new_value"])
            fixture_path.write_text(json.dumps(data))
            time.sleep(wait_sec)

            walk_suffix = walk_defs.get(walk_label, "")
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, *SNMP_STABLE_OUTPUT_ARGS,
                 f"127.0.0.1:{snmp_port}", f"{ent_oid}{walk_suffix}"],
                capture_output=True, text=True, env=snmp_env,
            )
            new_walk_path = output_dir / f"snmpwalk-stability-{safe_check}-{mut_idx}.txt"
            new_walk_path.write_text(result.stdout + result.stderr)

            symbols: list[str] = []
            mut_oid_failed = 0
            for oid in resolved:
                before_val = before.get(oid)
                if before_val is None:
                    symbols.append(_dim("?"))
                    continue
                after_val = extract_oid_value(new_walk_path, ent_oid, oid)
                changed = (before_val != after_val)
                is_expected = (oid == expected_oid)

                if changed and is_expected:
                    symbols.append(_green("!"))
                    oid_passed += 1
                elif not changed and not is_expected:
                    symbols.append(_dim("."))
                    oid_passed += 1
                elif changed and not is_expected:
                    symbols.append(_red("!"))
                    oid_failed += 1
                    mut_oid_failed += 1
                    failures.append(
                        f"FAIL: unexpected LastChange advance in '{label}'\n"
                        f"      oid    : {ent_oid}{oid}\n"
                        f"      before : {before_val}\n"
                        f"      after  : {after_val}"
                    )
                else:
                    symbols.append(_red("."))
                    oid_failed += 1
                    mut_oid_failed += 1
                    failures.append(
                        f"FAIL: expected LastChange did not advance in '{label}'\n"
                        f"      oid    : {ent_oid}{expected_oid}"
                    )

            if mut_oid_failed == 0:
                mut_passed += 1
            else:
                mut_failed += 1

            print(f"  {''.join(symbols)}  {_dim(label)}")
            before = {oid: extract_oid_value(new_walk_path, ent_oid, oid) for oid in resolved}

    finally:
        fixture_path.write_bytes(original_bytes)

    return mut_passed, mut_failed, oid_passed, oid_failed, failures


def run_stability_checks(cfg: dict, live_fixtures: Path,
                         ent_oid: str, all_indices: dict[str, str],
                         snmp_port: int, community: str,
                         walk_defs: dict, output_dir: Path,
                         snmp_env: dict[str, str],
                         walk_files: dict[str, Path],
                         verbose: bool,
                         section_filter: Optional[str]
                         ) -> tuple[int, int, int, list[tuple[str, list[str]]]]:
    total_pass = total_fail = total_skip = 0
    all_failures: list[tuple[str, list[str]]] = []

    for check in cfg.get("stability_checks", []):
        name = check.get("name", "(unnamed stability check)")
        if section_filter and section_filter.lower() not in name.lower():
            continue
        skip_reason = check.get("skip")
        if skip_reason:
            print_section_result(name, 0, 0, 1, skip_reason, [])
            total_skip += 1
            continue
        mp, mf, op, of, failures = run_stability_check(
            check, live_fixtures, ent_oid, all_indices,
            snmp_port, community, walk_defs, output_dir, snmp_env,
            walk_files, verbose,
        )
        mut_total = mp + mf
        oid_total = op + of
        parts = [f"{mp}/{mut_total} Passed", f"({op}/{oid_total} subtest passed)"]
        if mf:
            parts.append(_red(f"{mf} FAILED"))
        width = 28
        padded = f"--- {name} ---".ljust(width)
        print(f"{padded}  [{', '.join(parts)}]")
        total_pass += mp
        total_fail += mf
        if failures:
            all_failures.append((name, failures))

    return total_pass, total_fail, total_skip, all_failures


def run_section(section: dict, walk_files: dict[str, Path],
                ent_oid: str, all_indices: dict[str, str],
                verbose: bool) -> tuple[int, int, int, list[str]]:
    """Returns (passed, failed, skipped, failure_messages)."""
    passed = failed = skipped = 0
    failures: list[str] = []

    if section.get("skip"):
        return 0, 0, 1, []

    walk_label = section["walk"]
    walk_file = walk_files.get(walk_label)
    if walk_file is None:
        failures.append(f"walk file '{walk_label}' not found")
        return 0, 1, 0, failures

    device_key = section.get("device")
    device_idx = all_indices.get(device_key) if device_key else None

    tests = section.get("tests") or []
    if not tests:
        return 0, 0, 0, []

    for t in tests:
        label = t.get("label", "(unnamed)")
        ttype = t.get("type", "oid")

        if ttype == "rows":
            oid_regex = t["oid_regex"]
            if device_idx:
                oid_regex = oid_regex.replace("{D}", re.escape(device_idx))
            minimum = int(t.get("min", 1))
            ok, count = check_rows(ent_oid, walk_file, oid_regex, minimum)
            if ok:
                passed += 1
            else:
                failed += 1
                failures.append(
                    f"FAIL: {label}\n"
                    f"      oid_regex : {ent_oid}{oid_regex}\n"
                    f"      expected  : >= {minimum} rows\n"
                    f"      found     : {count} rows"
                )

        else:  # type == "oid"
            tmpl = section.get("oid_template")
            if tmpl is not None and "col" in t:
                oid_raw = tmpl.replace("{col}", str(t["col"]))
                if "{inst}" in oid_raw:
                    oid_raw = oid_raw.replace("{inst}", str(t.get("inst", "")))
            else:
                oid_raw = t["oid"]
            oid_suffix = substitute_oid(oid_raw, device_idx, all_indices)
            expected_re = t["expected"]
            ok, actual = check_oid(ent_oid, walk_file, oid_suffix, expected_re)
            if ok:
                passed += 1
            else:
                failed += 1
                found_str = actual if actual else "(no matching OID in walk file)"
                failures.append(
                    f"FAIL: {label}\n"
                    f"      oid      : {ent_oid}{oid_suffix}\n"
                    f"      expected : {expected_re}\n"
                    f"      found    : {found_str}"
                )

    return passed, failed, skipped, failures


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------

def print_section_result(name: str, passed: int, failed: int, skipped: int,
                         skip_reason: Optional[str], failures: list[str]) -> None:
    width = 28
    padded = f"--- {name} ---".ljust(width)

    if skip_reason:
        print(f"{_dim(padded)}  [{_yellow(f'SKIPPED: {skip_reason}')}]")
        return

    total = passed + failed
    if total == 0:
        print(f"{_dim(padded)}  [{_dim('no tests')}]")
        return

    if failed == 0:
        summary = _green(f"{passed}/{total} passed")
        if skipped:
            summary += f", {_yellow(str(skipped) + ' skipped')}"
        print(f"{padded}  [{summary}]")
    else:
        summary = _red(f"{passed}/{total} passed, {failed} FAILED")
        if skipped:
            summary += f", {_yellow(str(skipped) + ' skipped')}"
        print(f"{padded}  [{summary}]")


# ---------------------------------------------------------------------------
# Notification (trap delivery) tests
# ---------------------------------------------------------------------------

def run_notification_test(notif: dict, live_fixtures: Path, fixture_variants: Path,
                          trap_log: Path, ent_oid: str,
                          all_indices: dict[str, str]) -> tuple[int, int, list[str]]:
    """Apply a fixture action, wait, verify traps received."""
    passed = failed = 0
    failures: list[str] = []

    action = notif.get("action", "replace")
    trigger_name = notif.get("trigger_fixture", "")
    replace_name = notif.get("replace_fixture", "")
    target_name = notif.get("target_fixture", "")
    setup_name = notif.get("setup_fixture", "")
    wait_sec = float(notif.get("wait_seconds", 3.0))
    expected_traps = notif.get("expected_traps", [])

    if action == "replace":
        trigger_path = fixture_variants / trigger_name
        replace_path = live_fixtures / replace_name
        if not trigger_path.exists():
            failures.append(f"FAIL: trigger fixture not found: {trigger_path}")
            return 0, 1, failures
        if not replace_path.exists():
            failures.append(f"FAIL: live fixture not found: {replace_path}")
            return 0, 1, failures
        trap_before = trap_log.read_text() if trap_log.exists() else ""
        shutil.copy2(trigger_path, replace_path)
    elif action == "add":
        trigger_path = fixture_variants / trigger_name
        target_path = live_fixtures / (target_name or trigger_name)
        if not trigger_path.exists():
            failures.append(f"FAIL: trigger fixture not found: {trigger_path}")
            return 0, 1, failures
        if target_path.exists():
            failures.append(f"FAIL: live fixture already exists: {target_path}")
            return 0, 1, failures
        trap_before = trap_log.read_text() if trap_log.exists() else ""
        shutil.copy2(trigger_path, target_path)
    elif action == "remove":
        target_path = live_fixtures / (target_name or replace_name)
        if not target_path.exists() and setup_name:
            setup_path = fixture_variants / setup_name
            if not setup_path.exists():
                failures.append(f"FAIL: setup fixture not found: {setup_path}")
                return 0, 1, failures
            shutil.copy2(setup_path, target_path)
            time.sleep(wait_sec)
        if not target_path.exists():
            failures.append(f"FAIL: live fixture not found: {target_path}")
            return 0, 1, failures
        trap_before = trap_log.read_text() if trap_log.exists() else ""
        target_path.unlink()
    else:
        failures.append(f"FAIL: unsupported notification action: {action}")
        return 0, 1, failures

    time.sleep(wait_sec)
    trap_after = trap_log.read_text() if trap_log.exists() else ""
    new_trap_text = trap_after[len(trap_before):]

    if not expected_traps:
        if new_trap_text.strip():
            passed += 1
        else:
            failed += 1
            failures.append(f"FAIL: no trap received after fixture swap\n      traplog: {trap_log}")
    else:
        for et in expected_traps:
            oid_suffix = substitute_oid(et.get("oid_suffix", ""), None, all_indices)
            value_pat = et.get("value_pattern", ".*")
            oid_full = f"{ent_oid}{oid_suffix}"
            oid_forms = [re.escape(oid_full)]
            if oid_full.startswith("1.3.6.1.4.1."):
                oid_forms.append(re.escape("enterprises." + oid_full[len("1.3.6.1.4.1."):]))
            pattern = re.compile(rf"(?:{'|'.join(oid_forms)}).*{value_pat}")
            if pattern.search(new_trap_text):
                passed += 1
            else:
                failed += 1
                failures.append(
                    f"FAIL: trap OID not received\n"
                    f"      oid     : {oid_full}\n"
                    f"      pattern : {value_pat}\n"
                    f"      traplog : {trap_log}"
                )

    return passed, failed, failures


def run_notifications(cfg: dict, live_fixtures: Path, fixture_variants: Path,
                      trap_log: Path, ent_oid: str,
                      all_indices: dict[str, str],
                      section_filter: Optional[str]
                      ) -> tuple[int, int, int, list[tuple[str, list[str]]]]:
    total_pass = total_fail = total_skip = 0
    all_failures: list[tuple[str, list[str]]] = []

    for notif in cfg.get("notifications", []):
        name = notif.get("name", "(unnamed notification)")
        if section_filter and section_filter.lower() not in name.lower():
            continue
        skip_reason = notif.get("skip")
        if skip_reason:
            print_section_result(name, 0, 0, 1, skip_reason, [])
            total_skip += 1
            continue
        p, f, failures = run_notification_test(
            notif, live_fixtures, fixture_variants, trap_log, ent_oid, all_indices
        )
        print_section_result(name, p, f, 0, None, failures)
        total_pass += p
        total_fail += f
        if failures:
            all_failures.append((name, failures))

    return total_pass, total_fail, total_skip, all_failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="smartmon-snmp-agentxd integration test")
    script_dir = Path(__file__).parent
    p.add_argument("--config",   default=str(script_dir / "integration_test.yaml"))
    p.add_argument("--fixtures", default=os.environ.get("FIXTURES", ""))
    p.add_argument("--output",   default=os.environ.get("OUTPUT", ""))
    p.add_argument("--binary",   default=os.environ.get("AGENTXD_BIN", ""))
    p.add_argument("--verbose",  action="store_true")
    p.add_argument("--section",  metavar="NAME", help="run only sections matching this substring")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    c = cfg["config"]

    repo_root = Path(__file__).parent.parent.resolve()

    # Resolve fixtures and output dirs
    fixtures_src = args.fixtures or str(repo_root / "tests" / "fixtures")
    if not Path(fixtures_src).is_dir():
        die(f"fixture directory not found: {fixtures_src}")
    if not list(Path(fixtures_src).glob("*.json")):
        die(f"no JSON fixtures found in {fixtures_src}")

    output_dir = Path(args.output or str(repo_root / ".tmp" / "test"))
    output_dir.mkdir(parents=True, exist_ok=True)

    binary = find_binary(cfg, repo_root, args.binary or None)
    snmp_env = build_snmp_env(repo_root)

    require_cmd("snmpd")
    require_cmd("snmpwalk")
    require_cmd("snmpget")

    ent_oid   = c["ent_oid"]
    community = c["community"]
    snmp_port = int(os.environ.get("SNMP_PORT", c["snmp_port_base"] + os.getpid() % 1000))
    trap_port = int(os.environ.get("TRAP_PORT", c["trap_port_base"] + os.getpid() % 1000))
    poll_attempts = int(c.get("agentx_register_poll_attempts", 40))
    poll_interval = float(c.get("agentx_register_poll_interval", 0.5))

    # Log files
    agentxd_log  = output_dir / "agentxd.log"
    snmpd_log    = output_dir / "snmpd.log"
    trap_log     = output_dir / "trapd.log"
    register_log = output_dir / "register-poll.log"
    run_info     = output_dir / "run-info.txt"

    for f in (agentxd_log, snmpd_log, trap_log, register_log):
        f.write_text("")

    run_dir = Path(tempfile.mkdtemp(prefix="agentx-test-"))
    socket_path = run_dir / "master"

    daemons = DaemonSet()

    def cleanup():
        daemons.stop_all()
        shutil.rmtree(run_dir, ignore_errors=True)

    # Register cleanup on signals
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, f: (cleanup(), sys.exit(1)))

    try:
        # Setup fixture directories
        live_fixtures, fixture_variants = setup_fixtures(
            fixtures_src, run_dir, cfg["fixture_variants"]["patterns"]
        )

        fixture_count = len(list(live_fixtures.glob("*.json")))

        print(_bold(f"=== Integration test: smartmon-snmp-agentxd ==="))
        print(f"  binary  : {binary}")
        print(f"  fixtures: {live_fixtures} ({fixture_count} JSON files)")
        print(f"  output  : {output_dir}")
        print(f"  snmp    : 127.0.0.1:{snmp_port}")

        run_info.write_text(
            f"timestamp={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"fixtures={live_fixtures}\n"
            f"output={output_dir}\n"
            f"agentxd_bin={binary}\n"
            f"snmp_host=127.0.0.1:{snmp_port}\n"
            f"trap_port={trap_port}\n"
            f"mibs={snmp_env.get('MIBS', '')}\n"
            f"mibdirs={snmp_env.get('MIBDIRS', '')}\n"
        )

        # Start daemons
        trapd_pid = start_snmptrapd(run_dir, trap_port, trap_log, daemons, snmp_env)
        if trapd_pid:
            print(f"  snmptrapd pid={trapd_pid} port={trap_port}")

        print("  starting snmpd ...")
        snmpd_pid = start_snmpd(
            run_dir, socket_path, snmp_port, trap_port, community, snmpd_log, daemons, snmp_env
        )
        print(f"  snmpd ready (pid={snmpd_pid})")

        print("  starting smartmon-snmp-agentxd ...")
        agentxd_pid = start_agentxd(binary, run_dir, socket_path, live_fixtures, agentxd_log, daemons)

        wait_for_registration(
            snmp_port, ent_oid, community,
            poll_attempts, poll_interval,
            register_log, snmp_env, agentxd_log, snmpd_log,
        )
        print(f"  agentxd registered (pid={agentxd_pid})")

        with open(run_info, "a") as ri:
            ri.write(f"agentxd_pid={agentxd_pid}\nsnmpd_pid={snmpd_pid}\n")

        # Walks
        print()
        walk_defs = cfg.get("walks", {})
        walk_files = run_walks(ent_oid, snmp_port, community, walk_defs, output_dir, snmp_env)
        for label, wfile in walk_files.items():
            lines = len(wfile.read_text().splitlines())
            print(f"  walked {label}: {lines} lines -> snmpwalk-{label}.txt")

        # Discovery
        indices = discover_all(cfg, walk_files, ent_oid)
        print()
        print(_bold("=== Device indices ==="))
        for dev_key, idx in indices.items():
            dev = cfg["discovery"][dev_key]
            print(f"  {dev['label']}: {idx}")

        # Run test sections
        print()
        total_pass = total_fail = total_skip = 0
        all_section_failures: list[tuple[str, list[str]]] = []

        section_filter = args.section
        for section in cfg.get("sections", []):
            name = section.get("name", "(unnamed)")
            if section_filter and section_filter.lower() not in name.lower():
                continue

            skip_reason = section.get("skip")
            if skip_reason:
                print_section_result(name, 0, 0, 1, skip_reason, [])
                total_skip += 1
                continue

            p, f, s, failures = run_section(section, walk_files, ent_oid, indices, args.verbose)
            print_section_result(name, p, f, s, None, failures)
            total_pass += p
            total_fail += f
            total_skip += s
            if failures:
                all_section_failures.append((name, failures))

        # Stability checks (re-parse unchanged fixture, verify no LastChange advance)
        sp, sf, ss, stab_failures = run_stability_checks(
            cfg, live_fixtures, ent_oid, indices,
            snmp_port, community, walk_defs, output_dir, snmp_env,
            walk_files, args.verbose, section_filter,
        )
        total_pass += sp
        total_fail += sf
        total_skip += ss
        all_section_failures.extend(stab_failures)

        # Notification (trap delivery) tests
        np, nf, ns, notif_failures = run_notifications(
            cfg, live_fixtures, fixture_variants, trap_log, ent_oid, indices, section_filter
        )
        total_pass += np
        total_fail += nf
        total_skip += ns
        all_section_failures.extend(notif_failures)

        # Print collected failures
        if all_section_failures:
            print()
            print(_bold("=== Failures ==="))
            for sec_name, msgs in all_section_failures:
                print(f"  [{_bold(sec_name)}]")
                for msg in msgs:
                    for line in msg.splitlines():
                        print(f"    {_red(line) if line.startswith('FAIL') else line}")

        # Final summary
        print()
        result_label = _green("PASSED") if total_fail == 0 else _red("FAILED")
        summary = f"=== Results: {total_pass} passed, {total_fail} failed, {total_skip} skipped — {result_label} ==="
        print(_bold(summary))

        return 0 if total_fail == 0 else 1

    finally:
        cleanup()


if __name__ == "__main__":
    sys.exit(main())
