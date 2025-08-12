#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import inspect
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.bypass import WAFBypass
from utils import bypass as bypass_mod

LOG_FMT = "%(asctime)s | %(levelname)s | %(message)s"
logging.basicConfig(level=logging.DEBUG, format=LOG_FMT)
log = logging.getLogger("main")

ENTRY_CANDIDATES = ["run", "start", "execute", "scan", "process", "__call__", "main"]

def _normalize_methods_in_argv(argv: list[str]) -> list[str]:
    out, i = [], 0
    while i < len(argv):
        tok = argv[i]
        out.append(tok)
        if tok == "--methods" and i + 1 < len(argv):
            j, bucket = i + 1, []
            while j < len(argv) and not argv[j].startswith("--"):
                bucket.append(argv[j])
                j += 1
            if len(bucket) > 1:
                out.append(",".join(bucket))
            elif len(bucket) == 1:
                out.append(bucket[0])
            i = j
            continue
        i += 1
    return out

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bypass", add_help=True)

    p.add_argument("--host", required=True)
    p.add_argument("--methods", default="GET,POST")
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--rps", type=int, default=6)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--retry-backoff", dest="retry_backoff", type=float, default=0.5)
    p.add_argument("--dns-callback", dest="dns_callback", default=None)
    p.add_argument("--discover", action="store_true")
    p.add_argument("--discover-max", dest="discover_max", type=int, default=80)
    p.add_argument("--path-file", dest="path_file", default=None)
    p.add_argument("--paths", nargs="*", default=None)
    p.add_argument("--csv-out", dest="csv_out", default=None)
    p.add_argument("--details", action="store_true")
    p.add_argument("--sticky-session", action="store_true")
    p.add_argument("--verify-challenge", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--heuristics_mode", choices=["off", "cautious", "strict"], default="cautious")  # Thêm dòng này

    return p

def _filter_kwargs_for_callable(kwargs: dict, func) -> dict:
    try:
        sig = inspect.signature(func)
        accepted = set(sig.parameters.keys())
        return {k: v for k, v in kwargs.items() if k in accepted}
    except (ValueError, TypeError):
        return {}

def _pick_entrypoint_from_obj(obj):
    for name in ENTRY_CANDIDATES:
        if hasattr(obj, name):
            fn = getattr(obj, name)
            if callable(fn):
                return name, fn
    return None, None

def main() -> int:
    argv = _normalize_methods_in_argv(sys.argv[1:])
    args = _build_parser().parse_args(argv)

    methods = []
    if args.methods:
        raw = args.methods.replace(" ", ",")
        methods = [m.strip().upper() for m in raw.split(",") if m.strip()]

    all_kwargs = dict(
        host=args.host,
        methods=methods,
        threads=args.threads,
        rps=args.rps,
        retries=args.retries,
        retry_backoff=args.retry_backoff,
        dns_callback=args.dns_callback,
        discover=args.discover,
        discover_max=args.discover_max,
        path_file=args.path_file,
        paths=args.paths,
        csv_out=args.csv_out,
        details=args.details,
        sticky_session=args.sticky_session,
        verify_challenge=args.verify_challenge,
        insecure=args.insecure,
        heuristics_mode=args.heuristics_mode,  # Thêm dòng này
    )

    if all_kwargs.get("dns_callback") is not None:
        all_kwargs.setdefault("dns_cb", all_kwargs["dns_callback"])

    print("\n[ Scan Configuration ]")
    print(f"Target:       {args.host}")
    print(f"Methods:      {', '.join(methods) if methods else 'GET'}")
    print(f"Threads:      {args.threads}")
    print(f"RPS:          {args.rps}")
    print(f"Retries:      {args.retries}")
    print(f"Backoff:      {args.retry_backoff}")
    print(f"DNS Callback: {args.dns_callback or 'Not used'}")
    if args.discover:
        print(f"Discover:     ON (max {args.discover_max})")
    if args.csv_out:
        print(f"CSV Out:      {args.csv_out}")
    print()

    init_kwargs = _filter_kwargs_for_callable(all_kwargs, WAFBypass.__init__)
    log.debug("Khởi tạo WAFBypass với tham số: %s", sorted(init_kwargs.keys()))
    scanner = WAFBypass(**init_kwargs)

    name, fn = _pick_entrypoint_from_obj(scanner)
    if fn is not None:
        run_kwargs = _filter_kwargs_for_callable(all_kwargs, fn)
        log.debug("Entrypoint: WAFBypass.%s(%s)", name, ", ".join(sorted(run_kwargs.keys())))
        try:
            summary = fn(**run_kwargs)
        except Exception as ex:
            log.exception("Lỗi khi gọi WAFBypass.%s(): %s", name, ex)
            return 2
    else:
        mod_name, mod_fn = _pick_entrypoint_from_obj(bypass_mod)
        if mod_fn is None:
            log.error("Không tìm thấy entrypoint nào trong WAFBypass hoặc utils/bypass.py")
            return 3
        run_kwargs = _filter_kwargs_for_callable(all_kwargs, mod_fn)
        log.debug("Entrypoint: utils.bypass.%s(%s)", mod_name, ", ".join(sorted(run_kwargs.keys())))
        try:
            summary = mod_fn(**run_kwargs)
        except Exception as ex:
            log.exception("Lỗi khi gọi utils.bypass.%s(): %s", mod_name, ex)
            return 2

    if isinstance(summary, dict):
        b = summary.get("BLOCKED", 0)
        bp = summary.get("BYPASSED", 0)
        p = summary.get("PASSED", 0)
        f = summary.get("FALSED", 0)
        ch = summary.get("CHALLENGE", 0)
        log.info("Tổng kết: BLOCKED=%s | BYPASSED=%s | PASSED=%s | FALSED=%s | CHALLENGE=%s", b, bp, p, f, ch)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())