#!/usr/bin/env python3
"""ci/run_integration_test_v3.py — live SNMP integration test for smartmon-snmp-agentxd."""

import argparse
import fnmatch
import glob
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

    def start(self, *args, stdout=None, stderr=None) -> int:
        proc = subprocess.Popen(list(args), stdout=stdout, stderr=stderr)
        self.pids.append(proc.pid)
        return proc.pid

    def stop_all(self) -> None:
        for pid in self.pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        self.pids.clear()


def start_snmptrapd(run_dir: Path, trap_port: int, trap_log: Path, daemons: DaemonSet) -> Optional[int]:
    if not shutil.which("snmptrapd"):
        return None
    conf = run_dir / "snmptrapd.conf"
    conf.write_text("disableAuthorization yes\n")
    pid = daemons.start(
        "snmptrapd", "-f", "-Lo", "-C", "-c", str(conf),
        f"udp:127.0.0.1:{trap_port}",
        stdout=open(trap_log, "w"), stderr=subprocess.STDOUT,
    )
    return pid


def start_snmpd(run_dir: Path, socket_path: Path, snmp_port: int,
                trap_port: int, community: str, snmpd_log: Path,
                daemons: DaemonSet) -> int:
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
                           register_log: Path,
                           agentxd_log: Path, snmpd_log: Path) -> None:
    with open(register_log, "w") as rlog:
        for i in range(1, attempts + 1):
            rlog.write(f"--- attempt {i} ---\n")
            result = subprocess.run(
                ["snmpget", "-v2c", "-c", community, "-On",
                 f"127.0.0.1:{snmp_port}", f"{ent_oid}.2.1.1.0"],
                capture_output=True, text=True,
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
              walk_defs: dict, output_dir: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for label, suffix in walk_defs.items():
        oid = f"{ent_oid}{suffix}"
        outfile = output_dir / f"snmpwalk-{label}.txt"
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-On",
             f"127.0.0.1:{snmp_port}", oid],
            capture_output=True, text=True,
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
                          trap_log: Path, ent_oid: str) -> tuple[int, int, list[str]]:
    """Copy trigger fixture over live fixture, wait, verify traps received."""
    passed = failed = 0
    failures: list[str] = []

    trigger_name = notif.get("trigger_fixture", "")
    replace_name = notif.get("replace_fixture", "")
    wait_sec = float(notif.get("wait_seconds", 3.0))
    expected_traps = notif.get("expected_traps", [])

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
            oid_suffix = et.get("oid_suffix", "")
            value_pat = et.get("value_pattern", ".*")
            oid_full = f"{ent_oid}{oid_suffix}"
            pattern = re.compile(rf"{re.escape(oid_full)}.*{value_pat}")
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
            notif, live_fixtures, fixture_variants, trap_log, ent_oid
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
    p = argparse.ArgumentParser(description="smartmon-snmp-agentxd integration test v3")
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

    run_dir = Path(tempfile.mkdtemp(prefix="agentx-test-v3-"))
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

        print(_bold(f"=== Integration test v3: smartmon-snmp-agentxd ==="))
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
        )

        # Start daemons
        trapd_pid = start_snmptrapd(run_dir, trap_port, trap_log, daemons)
        if trapd_pid:
            print(f"  snmptrapd pid={trapd_pid} port={trap_port}")

        print("  starting snmpd ...")
        snmpd_pid = start_snmpd(
            run_dir, socket_path, snmp_port, trap_port, community, snmpd_log, daemons
        )
        print(f"  snmpd ready (pid={snmpd_pid})")

        print("  starting smartmon-snmp-agentxd ...")
        agentxd_pid = start_agentxd(binary, run_dir, socket_path, live_fixtures, agentxd_log, daemons)

        wait_for_registration(
            snmp_port, ent_oid, community,
            poll_attempts, poll_interval,
            register_log, agentxd_log, snmpd_log,
        )
        print(f"  agentxd registered (pid={agentxd_pid})")

        with open(run_info, "a") as ri:
            ri.write(f"agentxd_pid={agentxd_pid}\nsnmpd_pid={snmpd_pid}\n")

        # Walks
        print()
        walk_defs = cfg.get("walks", {})
        walk_files = run_walks(ent_oid, snmp_port, community, walk_defs, output_dir)
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

        # Notification (trap delivery) tests
        np, nf, ns, notif_failures = run_notifications(
            cfg, live_fixtures, fixture_variants, trap_log, ent_oid, section_filter
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
