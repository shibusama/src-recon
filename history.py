#!/usr/bin/env python3
"""
步骤 5：历史记录查询 — Wayback Machine + DNS 历史 + ICP 备案

用法：
  python3 history.py example.com
  python3 history.py example.com --skip-icp
"""
import argparse
import re
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import log, save_json, HEADERS, OUTPUT_DIR


requests.packages.urllib3.disable_warnings()


def fetch_wayback_urls(domain, limit=500):
    log("  查询 Wayback Machine 历史存档...")
    try:
        resp = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,timestamp,statuscode&limit={limit}&collapse=urlkey",
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                urls = set()
                paths = set()
                for row in data[1:]:
                    if row:
                        urls.add(row[0])
                        from urllib.parse import urlparse
                        parsed = urlparse(row[0])
                        if parsed.path and parsed.path != "/":
                            paths.add(parsed.path)
                log(f"  Wayback → {len(urls)} 个 URL, {len(paths)} 个路径", "ok")
                return {"urls": sorted(urls), "paths": sorted(paths)}
    except Exception as e:
        log(f"  Wayback 查询失败: {e}", "warn")
    return {"urls": [], "paths": []}


def query_dns_history(domain):
    log("  查询 DNS 历史记录...")
    history = {"a": []}

    # SecurityTrails
    try:
        resp = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/history/a",
            headers={"Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("records", []):
                if record.get("type") == "A":
                    for r in record.get("values", []):
                        if r.get("ip"):
                            history["a"].append(r["ip"])
            history["a"] = list(set(history["a"]))
            if history["a"]:
                log(f"  SecurityTrails → {len(history['a'])} 个历史 IP", "ok")
                return history
    except Exception:
        pass

    # ViewDNS 备选
    try:
        resp = requests.get(
            f"https://viewdns.info/iphistory/?domain={domain}",
            headers=HEADERS, timeout=15,
        )
        if resp.status_code == 200:
            ips = re.findall(r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td>', resp.text)
            if ips:
                history["a"] = ips[:20]
                log(f"  ViewDNS → {len(ips)} 个历史 IP", "ok")
                return history
    except Exception:
        pass

    log("  DNS 历史查询无结果", "warn")
    return history


def query_icp(domain):
    log("  查询 ICP 备案信息...")
    try:
        resp = requests.get(
            f"https://api.regini.cn/api/icp?domain={domain}",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("code") == 200:
                info = {
                    "unit": data.get("data", {}).get("unitName", ""),
                    "icp": data.get("data", {}).get("icp", ""),
                }
                log(f"  ICP 备案 → {info['unit']} ({info['icp']})", "ok")
                return info
    except Exception:
        pass

    log("  ICP 备案查询无结果", "warn")
    return {}


def main():
    parser = argparse.ArgumentParser(description="步骤5: 历史记录查询")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("--skip-icp", action="store_true", help="跳过 ICP 查询")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    args = parser.parse_args()

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
        OUTPUT_DIR.mkdir(exist_ok=True)

    domain = args.domain.strip()
    if domain.startswith("http"):
        domain = re.sub(r"https?://", "", domain).rstrip("/")

    log(f"开始查询 {domain} 的历史记录")
    log("=" * 50)

    wayback = fetch_wayback_urls(domain)
    if wayback.get("paths"):
        save_json(wayback, f"{domain}_wayback.json")

    dns_hist = query_dns_history(domain)
    if dns_hist.get("a"):
        save_json(dns_hist, f"{domain}_dns_history.json")

    if not args.skip_icp:
        icp = query_icp(domain)
        if icp:
            save_json(icp, f"{domain}_icp.json")


if __name__ == "__main__":
    main()
