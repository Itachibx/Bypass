import json
from pathlib import Path
from typing import Any, Dict, Union
import random
import string
import logging

logger = logging.getLogger(__name__)

def _rand(n=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(int(n)))

def _substitute(s, dns_cb):
    if not isinstance(s, str):
        return s
    token = dns_cb or ""
    if token:
        s = s.replace("{{DNS}}", token)
        s = s.replace("%DNS%", token)
        s = s.replace("${DNS}", token)
        s = s.replace("{{DNS_SCHEMELESS}}", f"//{token}")
    while "%RND%" in s:
        s = s.replace("%RND%", _rand(6), 1)
    return s

def _walk_and_replace(obj, dns_cb):
    if isinstance(obj, dict):
        return {k: _walk_and_replace(v, dns_cb) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_replace(v, dns_cb) for v in obj]
    return _substitute(obj, dns_cb)

def _deep_replace(obj: Union[Dict[str, Any], list, str, int, float, bool, None], rnd: str, dns_cb: str = None, host: str = None, base_url: str = None) -> Union[Dict[str, Any], list, str, int, float, bool, None]:
    def _subst(s: str) -> str:
        if rnd is not None:
            s = s.replace("%RND%", rnd)
        if dns_cb:
            s = (
                s.replace("%DNS%", dns_cb)
                 .replace("{{DNS}}", dns_cb)
                 .replace("{{DNS_CALLBACK}}", dns_cb)
            )
        if host:
            s = s.replace("%HOST%", host).replace("{{HOST}}", host)
        if base_url:
            s = s.replace("%BASE_URL%", base_url).replace("{{BASE_URL}}", base_url)
        return s

    if isinstance(obj, str):
        return _subst(obj)
    if isinstance(obj, list):
        return [_deep_replace(i, rnd, dns_cb, host, base_url) for i in obj]
    if isinstance(obj, dict):
        return {k: _deep_replace(v, rnd, dns_cb, host, base_url) for k, v in obj.items()}
    return obj

def get_payload(path: Union[str, Path], rnd: str = "", **kwargs) -> Dict[str, Any]:
    dns_cb = kwargs.get("dns_cb")
    host = kwargs.get("host")
    base_url = kwargs.get("base_url")

    p = Path(path)
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Loaded JSON from {path}: {data}")
    except Exception as e:
        logger.error(f"Failed to load JSON from {path}: {e}")
        return {}

    # Handle if data is {'payload': [list of dicts]}
    if 'payload' in data and isinstance(data['payload'], list) and data['payload']:
        data = data['payload'][0]  # Take the first payload dict

    if isinstance(data, list):
        data = data[0] if data else {}

    if not isinstance(data, dict):
        data = {"RAW": data}

    data = _deep_replace(data, rnd=rnd, dns_cb=dns_cb, host=host, base_url=base_url)
    logger.debug(f"Processed payload from {path}: {data}")
    return data
