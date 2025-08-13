# -*- coding: utf-8 -*-
import os
import re
import csv
import time
import json
import random
import logging
import threading
import urllib.parse
import ast

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from .payloads import get_payload
except Exception:
    from payloads import get_payload

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

class WAFBypass:
    def __init__(
        self,
        *,
        host,
        proxy=None,
        headers=None,
        timeout=10,
        threads=8,
        exclude_dir=None,
        block_code=None,
        block_patterns=None,
        wb_result=None,
        wb_result_json=False,
        details=False,
        no_progress=False,
        replay=False,
        dns_callback=None,
        methods=None,
        insecure=False,
        rps=0.0,
        retries=0,
        retry_backoff=0.0,
        csv_out=None,
        heuristics_mode="cautious",
        verify_challenge=False,
        sticky_session=True,
        retry_on="429,500,502,503,504,timeout",
        no_retry_on="401,403",
        paths=None,
        bypass_codes=None,
    ):
        self.host = host.rstrip("/") + "/"
        self.proxy = proxy or {}
        self.headers_raw = headers or []
        self.timeout = int(timeout or 10)
        self.threads = int(threads or 8)
        self.exclude_dir = exclude_dir or []
        self.block_code = set(block_code or [301, 302, 403, 406, 429, 500, 501, 502, 503])
        self.block_patterns = block_patterns or []
        self.dns_callback = dns_callback
        self.methods = [m.strip().upper() for m in (methods or ["GET", "POST"])]
        self.verify_tls = not bool(insecure)

        self.rps = float(rps) if rps else 0.0
        self._min_interval = 1.0 / self.rps if self.rps > 0 else 0.0
        self.retries = int(retries or 0)
        self.retry_backoff = float(retry_backoff or 0.0)
        self.csv_out = csv_out

        self.heuristics_mode = (heuristics_mode or "cautious").lower()
        self.verify_challenge = bool(verify_challenge)
        self.sticky_session = True if sticky_session is None else bool(sticky_session)
        self.retry_on = [x.strip().lower() for x in (retry_on or "").split(",") if x.strip()]
        self.no_retry_on = [int(x.strip()) for x in (no_retry_on or "").split(",") if x.strip().isdigit()]

        self.paths = paths or ["/"]

        self.stats = {"BLOCKED": 0, "BYPASSED": 0, "PASSED": 0, "FALSED": 0, "CHALLENGE": 0}
        self.wb_result = wb_result or {}
        self.details = details
        self.no_progress = no_progress
        self.replay = replay

        self._lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._last_ts = 0.0
        self._tls = threading.local()

        self.baseline_code = None
        self.baseline_body = None
        self._stop = False

    @property
    def processed(self) -> int:
        return len(self.wb_result)

    def _parsed_headers(self) -> dict:
        d = {}
        for h in self.headers_raw:
            if not h or ":" not in h:
                continue
            k, v = h.split(":", 1)
            d[k.strip()] = v.strip()
        if "User-Agent" not in d:
            d["User-Agent"] = "WAFBypass/1.0"
        return d

    def _get_session(self) -> requests.Session:
        if self.sticky_session:
            s = getattr(self._tls, "session", None)
            if s is not None:
                return s

        s = requests.Session()
        s.trust_env = False

        if self.retries > 0:
            status_forcelist = [int(x) for x in self.retry_on if str(x).isdigit()]
            retry = Retry(
                total=self.retries,
                connect=self.retries,
                read=self.retries,
                backoff_factor=self.retry_backoff,
                status_forcelist=status_forcelist,
                allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
            )
            adapter = HTTPAdapter(max_retries=retry)
            s.mount("http://", adapter)
            s.mount("https://", adapter)

        if self.sticky_session:
            self._tls.session = s
        return s

    def _throttle(self):
        if not self._min_interval:
            return
        with self._rate_lock:
            now = time.time()
            wait = (self._last_ts + self._min_interval) - now
            if wait > 0:
                time.sleep(wait + random.uniform(0, 0.02))
            self._last_ts = time.time()

    def _heartbeat(self, interval=15):
        while not self._stop:
            s = self.stats
            logger.info(
                "Tiến độ: BLOCKED=%d | BYPASSED=%d | PASSED=%d | FALSED=%d | CHALLENGE=%d | processed=%d",
                s.get("BLOCKED", 0),
                s.get("BYPASSED", 0),
                s.get("PASSED", 0),
                s.get("FALSED", 0),
                s.get("CHALLENGE", 0),
                self.processed,
            )
            time.sleep(interval)

    def get_baseline(self):
        logger.info(f"Sending baseline request to {self.host}")
        try:
            self._throttle()
            s = self._get_session()
            r = s.get(self.host, timeout=self.timeout, verify=self.verify_tls, proxies=self.proxy or {})
            self.baseline_code = r.status_code
            self.baseline_body = r.text or ""
            logger.info(f"Baseline response: status={r.status_code}, body={r.text[:100]}")
        except Exception as e:
            logger.error(f"Baseline request failed: %s", e)
            self.baseline_code = 200
            self.baseline_body = ""

    def is_challenge(self, status_code: int, body: str, headers: dict) -> bool:
        if self.heuristics_mode == "off":
            return False
        try:
            text = (body or "")
            if not isinstance(text, str):
                text = str(text)
            hdr = headers or {}
            vendors = [r"cf-ray", r"cloudflare", r"imperva", r"incapsula", r"akamai", r"sucuri", r"bot\s*protection"]
            vendor_hit = any(re.search(v, text, re.I) for v in vendors) or any(re.search(v, str(hdr), re.I) for v in vendors)
            keys = [r"captcha", r"challenge", r"attention\s*required", r"just\s*a\s*moment"]
            key_hit = any(re.search(k, text, re.I) for k in keys)
            short_html = isinstance(text, str) and "<html" in text.lower() and len(text.strip()) < 800
            if self.heuristics_mode == "strict":
                return vendor_hit or key_hit or short_html
            return vendor_hit and (key_hit or short_html)
        except Exception:
            return False

    def classify(self, status_code: int, is_payload: bool, body: str, headers: dict, payload: str) -> str:
        logger.debug(f"Classifying: status_code={status_code}, is_payload={is_payload}, body={body[:100]}, headers={headers}")
        if status_code in self.block_code or self.is_challenge(status_code, body, headers):
            return "BLOCKED"
        if status_code == 200:
            if is_payload and payload and str(payload) in body:  # Check reflection
                return "BYPASSED_REFLECTED"  # True bypass
            elif is_payload:
                return "PASSED_NO_REFLECT"  # Passed but no impact
            return "PASSED"
        if not is_payload:
            return "PASSED"
        return "FALSED"

    def send_request(self, method: str, url: str, **kwargs):
        logger.debug(f"Sending {method} to {url} with kwargs: {kwargs}")
        try:
            self._throttle()
            s = self._get_session()
            r = s.request(method, url, timeout=self.timeout, verify=self.verify_tls, proxies=self.proxy or {}, **kwargs)
            logger.debug(f"Response for {url}: status={r.status_code}, body={r.text[:100]}")
            return r
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

    def _process_one(self, json_path: str):
        logger.info(f"Processing payload: {json_path}")
        try:
            payload_obj = get_payload(json_path, dns_cb=self.dns_callback)
            logger.debug(f"Loaded payload: {payload_obj}")
        except Exception as e:
            logger.error(f"Failed to load payload {json_path}: {e}")
            return

        if not payload_obj:
            logger.warning(f"Empty payload for {json_path}")
            return

        payloads = payload_obj if isinstance(payload_obj, list) else [payload_obj]
        ZONES_ALL = ("URL", "ARGS", "BODY", "HEADER", "COOKIE", "USER-AGENT", "REFERER")
        base_headers = self._parsed_headers()

        for payload in payloads:
            if not isinstance(payload, dict):
                logger.warning(f"Invalid payload format in {json_path}: {payload}")
                continue

            has_zone = any(zone in payload for zone in ZONES_ALL)
            if not has_zone:
                logger.warning(f"No zone in {json_path}, fallback to ARGS")
                payload["ARGS"] = {"poc": str(payload)}

            # Fix for method parsing
            methods_in_payload = payload.get("METHOD")
            if methods_in_payload:
                if isinstance(methods_in_payload, str) and methods_in_payload.startswith("[") and methods_in_payload.endswith("]"):
                    try:
                        methods_list = ast.literal_eval(methods_in_payload)
                        if isinstance(methods_list, list):
                            methods_to_try = [m.strip().upper() for m in methods_list if m.strip()]
                        else:
                            methods_to_try = self.methods
                    except (ValueError, SyntaxError):
                        methods_to_try = self.methods
                else:
                    raw = methods_in_payload.replace(" ", ",")
                    methods_to_try = [m.strip().upper() for m in raw.split(",") if m.strip()]
            else:
                methods_to_try = self.methods

            for path in self.paths:
                base_url = urllib.parse.urljoin(self.host, path)

                for method in methods_to_try:
                    for zone in ZONES_ALL:
                        if zone not in payload or payload.get(zone) in (None, "", {}, []):
                            logger.debug(f"Skipping empty/invalid zone {zone} for {json_path}")
                            continue

                        req_kwargs = {"headers": dict(base_headers), "allow_redirects": False}
                        url = base_url

                        # Setup req_kwargs for zone
                        if zone == "URL" and isinstance(payload["URL"], str):
                            url = urllib.parse.urljoin(base_url, payload["URL"])
                        elif zone == "ARGS" and isinstance(payload["ARGS"], dict):
                            url = f"{base_url}?{urllib.parse.urlencode(payload['ARGS'])}"
                        elif zone == "BODY":
                            req_kwargs["data"] = payload["BODY"]
                        elif zone == "HEADER" and isinstance(payload["HEADER"], dict):
                            req_kwargs["headers"].update(payload["HEADER"])
                        elif zone == "COOKIE" and isinstance(payload["COOKIE"], dict):
                            req_kwargs["cookies"] = payload["COOKIE"]
                        elif zone == "USER-AGENT":
                            req_kwargs["headers"]["User-Agent"] = payload["USER-AGENT"]
                        elif zone == "REFERER":
                            req_kwargs["headers"]["Referer"] = payload["REFERER"]

                        r = self.send_request(method, url, **req_kwargs)
                        key = f"{path}:{json_path}::{method}::{zone}"

                        with self._lock:
                            if r is None:
                                self.wb_result[key] = {"status": "FAILED", "code": None, "payload": payload.get(zone)}
                            else:
                                body = r.text or ""
                                status = self.classify(r.status_code, True, body, r.headers, payload.get(zone))  # Pass payload for reflection check
                                self.wb_result[key] = {"status": status, "code": r.status_code, "payload": payload.get(zone)}
                                if status in self.stats:
                                    self.stats[status] += 1
                                if status == "BYPASSED_REFLECTED":
                                    logger.info(f"TRUE BYPASSED (REFLECTED): {key} with payload {payload.get(zone)}")
                                elif status == "PASSED_NO_REFLECT":
                                    logger.info(f"PASSED but NO REFLECT: {key} with payload {payload.get(zone)}")
                                elif status == "BLOCKED":
                                    logger.info(f"BLOCKED: {key} with code {r.status_code}")

    def start(self):
        logger.info(f"Starting scan for {self.host}")
        self.get_baseline()

        hb = threading.Thread(target=self._heartbeat, args=(15,), daemon=True)
        hb.start()

        payload_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "payload")
        logger.info(f"Checking payload directory: {payload_dir}")
        found = []
        for root, dirs, files in os.walk(payload_dir):
            if any(ex and ex in root for ex in (self.exclude_dir or [])):
                continue
            for f in files:
                if f.lower().endswith(".json"):
                    found.append(os.path.join(root, f))
        logger.info("Tìm thấy %d payload JSON.", len(found))

        baseline_key = "BASELINE:/"
        self.wb_result[baseline_key] = {
            "status": "PASSED" if self.baseline_code == 200 else "PASSED",
            "code": self.baseline_code,
        }
        self.stats["PASSED"] += 1

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=self.threads or 4) as ex:
            futs = {ex.submit(self._process_one, p): p for p in found}
            done = 0
            last = time.time()
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as e:
                    logger.error("Lỗi worker %s: %s", futs[fut], e)
                done += 1
                if done % 20 == 0 or (time.time() - last) > 10:
                    s = self.stats
                    logger.info(
                        "Đã xử lý %d/%d payload | B=%d BP=%d CH=%d P=%d F=%d | processed=%d",
                        done,
                        len(futs),
                        s.get("BLOCKED", 0),
                        s.get("BYPASSED", 0),
                        s.get("CHALLENGE", 0),
                        s.get("PASSED", 0),
                        s.get("FALSED", 0),
                        self.processed,
                    )
                    last = time.time()

        if self.verify_challenge:
            original = self._min_interval
            self._min_interval = max(self._min_interval, 0.7)
            try:
                for key, val in list(self.wb_result.items()):
                    if val.get("status") != "CHALLENGE":
                        continue
                    try:
                        path, rest = key.split(":", 1)
                    except ValueError:
                        path, rest = "/", key
                    zone = rest.split("::")[-1] if "::" in rest else rest.split("_")[-1]
                    json_path = rest.split("::")[0] if "::" in rest else rest

                    obj = get_payload(json_path, dns_cb=self.dns_callback)
                    payload_orig = None
                    if isinstance(obj, list):
                        payload_orig = next((e for e in obj if isinstance(e, dict)), None)
                    elif isinstance(obj, dict):
                        payload_orig = obj
                    if not isinstance(payload_orig, dict):
                        continue

                    base = urllib.parse.urljoin(self.host, path)
                    req_kwargs = {"headers": self._parsed_headers(), "allow_redirects": False}
                    r = self.send_request("GET", base, **req_kwargs)
                    if r is None:
                        continue
                    label = self.classify(r.status_code, True, r.text or "", getattr(r, "headers", {}))
                    if label == "BYPASSED":
                        self.wb_result[key]["status"] = "BYPASSED"
                        self.stats["CHALLENGE"] = max(0, self.stats["CHALLENGE"] - 1)
                        self.stats["BYPASSED"] += 1
            finally:
                self._min_interval = original

        self._stop = True

        if self.csv_out:
            self.report()

        try:
            self.report_html(os.path.join(os.getcwd(), "waf_report.html"))
        except Exception as e:
            logger.error("Không tạo được HTML report: %s", e)

    def report(self):
        if not (self.csv_out and self.wb_result):
            return
        try:
            with open(self.csv_out, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["key", "status", "code", "path", "zone", "json_path", "category", "payload"])
                for key, val in self.wb_result.items():
                    path, rest = key.split(":", 1) if ":" in key else ("/", key)
                    zone = rest.split("::")[-1] if "::" in rest else rest.split("_")[-1]
                    json_path = rest.split("::")[0] if "::" in rest else rest
                    parts = os.path.normpath(json_path).split(os.sep)
                    category = parts[-2] if len(parts) >= 2 else ""
                    w.writerow([
                        key,
                        val.get("status"),
                        val.get("code"),
                        path,
                        zone,
                        json_path,
                        category,
                        str(val.get("payload"))[:500],
                    ])
            logger.info("Đã ghi CSV vào %s", self.csv_out)
        except Exception as e:
            logger.error("Không ghi được CSV: %s", e)

    def report_html(self, out_path):
        try:
            rows = []
            for key, val in (self.wb_result or {}).items():
                rows.append({
                    "key": key,
                    "status": val.get("status"),
                    "code": val.get("code"),
                    "payload": str(val.get("payload"))[:800],
                })
            parts = []
            parts.append("<!doctype html><meta charset='utf-8'><title>WAF Report</title>")
            parts.append(
                "<style>body{font-family:system-ui;margin:24px}"
                "table{border-collapse:collapse;width=100%}"
                "th,td{padding:8px;border-bottom:1px solid #eee;text-align:left}"
                ".status{font-weight:600}"
                ".BLOCKED{color:#16a34a}.BYPASSED{color:#ef4444}.PASSED{color:#2563eb}"
                ".FALSED{color:#b45309}.CHALLENGE{color:#92400e}</style>"
            )
            parts.append("<h1>WAF Test Report</h1>")
            s = self.stats
            parts.append(
                f"<p>BLOCKED: {s.get('BLOCKED',0)} | BYPASSED: {s.get('BYPASSED',0)} | "
                f"PASSED: {s.get('PASSED',0)} | FALSED: {s.get('FALSED',0)} | "
                f"CHALLENGE: {s.get('CHALLENGE',0)} | PROCESSED: {self.processed}</p>"
            )
            parts.append("<table><thead><tr><th>Key</th><th>Code</th><th>Status</th><th>Payload</th></tr></thead><tbody>")
            for r in rows:
                payload_safe = (r["payload"] or "").replace("<", "&lt;").replace(">", "&gt;")
                parts.append(
                    f"<tr><td>{r['key']}</td><td>{r['code']}</td>"
                    f"<td class='status {r['status']}'>{r['status']}</td>"
                    f"<td><code>{payload_safe}</code></td></tr>"
                )
            parts.append("</tbody></table>")
            html = "".join(parts)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info("Đã tạo HTML report: %s", out_path)
        except Exception as e:
            logger.error("Lỗi tạo HTML report: %s", e)
