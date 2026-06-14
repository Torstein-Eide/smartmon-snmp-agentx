#!/usr/bin/env python3
"""Direct, in-process micro-benchmark of the custom table handler.

Measures the agent's per-OID GET/GETNEXT cost WITHOUT snmpd, AgentX, or UDP: it
builds the oid_map from fixtures, populates the handler's view, then drives the
real `_custom_node_handler` with fabricated net-snmp request structures (reusing
the actual snmp_set_var_* C setters). This isolates the handler cost that a live
snmpwalk/snmpbulkwalk shares — without the client<->master transport that makes
GETBULK look faster than GETNEXT on the wire.

Usage:
  ci/bench_handler.py [--fixtures DIR] [--get-iters N] [--repeat N]
"""

import argparse
import ctypes
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import smartmon_agentx as m   # noqa: E402


def _oid_tuple(vb) -> tuple:
    v = vb.contents
    return tuple(v.name[: v.name_length])


def _make_varbind(api, oid: tuple):
    """Allocate a real net-snmp varbind initialised to `oid` (type NULL)."""
    head = api.netsnmp_variable_list_p()      # NULL list head
    name = (ctypes.c_ulong * len(oid))(*oid)
    asn_null = getattr(api, "ASN_NULL", 0x05)
    vbp = api.libnsa.snmp_varlist_add_variable(
        ctypes.byref(head), name, len(oid), asn_null, None, 0)
    if not vbp:
        raise RuntimeError("snmp_varlist_add_variable failed")
    return head, ctypes.cast(vbp, m._NsVarList_p)


def setup(fixtures: str):
    m._st.state_dir = fixtures
    m._st.collect = False
    m._st.ttl = 0
    m._refresh()
    if not m._st.oid_map:
        raise SystemExit(f"no oid_map built from {fixtures} (no fixtures?)")
    m._st.custom_vals, m._st.custom_oids = m._custom_tables_view(m._st.oid_map)
    api, _core = m._get_custom_api()
    return api, len(m._st.oid_map), len(m._st.custom_oids)


def make_reginfo(api, region: tuple):
    """A handler_registration whose rootoid spans every custom subtree, so one
    synthetic GETNEXT walk traverses all custom tables in a single region."""
    reg = api.netsnmp_handler_registration()
    root = (ctypes.c_ulong * len(region))(*region)
    reg.rootoid = ctypes.cast(root, api.c_oid_p)
    reg.rootoid_len = len(region)
    return reg, root   # keep `root` alive


def bench_getnext(api, repeat: int) -> tuple:
    """Full synthetic GETNEXT walk over every custom OID, `repeat` times.
    Returns (oids_per_pass, best_seconds)."""
    region = m.BASE_OID
    reg, _root = make_reginfo(api, region)
    reginfo = ctypes.pointer(reg)
    ri = m._NsAgentReqInfo(); ri.mode = m._MODE_GETNEXT
    reqinfo = ctypes.pointer(ri)

    best = None
    passes_oids = 0
    for _ in range(repeat):
        head, vb = _make_varbind(api, region)        # start at the region root
        rq = m._NsRequestInfo()
        rq.requestvb = vb
        rq.inclusive = 0
        rq.next = m._NsRequestInfo_p()               # NULL
        requests = ctypes.pointer(rq)

        count = 0
        t0 = time.perf_counter()
        while True:
            prev = _oid_tuple(vb)
            m._custom_node_handler(None, reginfo, reqinfo, requests)
            cur = _oid_tuple(vb)
            if cur == prev:                          # handler didn't advance -> end
                break
            count += 1
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
        passes_oids = count
        api.libnsa.snmp_free_varbind(head)
    return passes_oids, best


def bench_get(api, repeat: int) -> tuple:
    """GET of every custom OID in one handler call, `repeat` times (the request
    chain is built once, outside the timed region). Returns (n_oids, best_s)."""
    oids = m._st.custom_oids
    # Build the request chain + varbinds once (setup cost, not timed).
    keep = []
    head_req = None
    prev_req = None
    for oid in oids:
        h, vb = _make_varbind(api, oid)
        rq = m._NsRequestInfo()
        rq.requestvb = vb
        rq.inclusive = 0
        rq.next = m._NsRequestInfo_p()
        keep.append((h, vb, rq))
        if prev_req is None:
            head_req = rq
        else:
            prev_req.next = ctypes.pointer(rq)
        prev_req = rq

    region = m.BASE_OID
    reg, _root = make_reginfo(api, region)
    reginfo = ctypes.pointer(reg)
    ri = m._NsAgentReqInfo(); ri.mode = m._MODE_GET
    reqinfo = ctypes.pointer(ri)
    requests = ctypes.pointer(head_req)

    best = None
    for _ in range(repeat):
        t0 = time.perf_counter()
        m._custom_node_handler(None, reginfo, reqinfo, requests)
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
    for h, _vb, _rq in keep:
        api.libnsa.snmp_free_varbind(h)
    return len(oids), best


def _line(label: str, n: int, secs: float) -> None:
    us = secs / n * 1e6 if n else 0.0
    rate = n / secs if secs else 0.0
    print(f"  {label:22s} {secs*1000:8.2f} ms   {n:6d} OIDs   "
          f"{us:6.2f} us/OID   {rate:10.0f} OIDs/s")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixtures", default=str(REPO / "tests" / "fixtures"))
    ap.add_argument("--repeat", type=int, default=10,
                    help="timed passes; the best (min) is reported")
    args = ap.parse_args()

    api, n_map, n_custom = setup(args.fixtures)
    print(f"oid_map={n_map} entries; custom-handler OIDs={n_custom}; "
          f"repeat={args.repeat} (best of)")
    print("  (in-process: no snmpd, no AgentX, no UDP — pure handler cost)\n")

    n, s = bench_getnext(api, args.repeat)
    _line("GETNEXT walk (1/call)", n, s)
    n, s = bench_get(api, args.repeat)
    _line("GET (all in 1 call)", n, s)
    print("\n  GETBULK is identical to GETNEXT at the handler (the master "
          "decomposes\n  client GETBULK into per-OID AgentX GetNext), so it is "
          "not measured separately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
