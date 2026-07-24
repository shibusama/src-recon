#!/usr/bin/env python3
"""
步骤 1：资产收集 — 子域名收集（被动 6 源 + DNS 爆破）

用法：
  python3 collect.py example.com
  python3 collect.py example.com -o /path/to/output
"""
import argparse
import concurrent.futures
import re
import sys
from pathlib import Path

import dns.resolver
import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import log, save_json, HEADERS, COMMON_SUBS, OUTPUT_DIR


requests.packages.urllib3.disable_warnings()


# ── 被动收集 ────────────────────────────────────────────────

def crt_sh(domain):
    log("  查询 crt.sh 证书透明度日志...")
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers=HEADERS, timeout=30, verify=False,
        )
        if resp.status_code == 200:
            subs = set()
            for entry in resp.json():
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and "*" not in n:
                        subs.add(n)
            log(f"  crt.sh → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  crt.sh 请求失败: {e}", "warn")
    return set()


def hackertarget(domain):
    log("  查询 HackerTarget...")
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            headers=HEADERS, timeout=30,
        )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            subs = set()
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if parts and "." in parts[0]:
                    host = parts[0].strip().lower()
                    if host.endswith(f".{domain}"):
                        subs.add(host)
            log(f"  HackerTarget → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  HackerTarget 请求失败: {e}", "warn")
    return set()


def rapiddns(domain):
    log("  查询 RapidDNS...")
    try:
        resp = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            headers=HEADERS, timeout=30,
        )
        if resp.status_code == 200:
            subs = set(re.findall(r">([\w.\-]+\." + re.escape(domain) + r")<", resp.text))
            log(f"  RapidDNS → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  RapidDNS 请求失败: {e}", "warn")
    return set()


def alienvault_otx(domain):
    log("  查询 AlienVault OTX...")
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=HEADERS, timeout=30, verify=False,
        )
        if resp.status_code == 200:
            subs = set()
            for entry in resp.json().get("passive_dns", []):
                h = entry.get("hostname", "").lower()
                if h.endswith(f".{domain}") and "*" not in h:
                    subs.add(h)
            log(f"  AlienVault OTX → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  AlienVault OTX 请求失败: {e}", "warn")
    return set()


def dnsdumpster(domain):
    log("  查询 DNSDumpster...")
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        resp = session.get("https://dnsdumpster.com/", timeout=15)
        csrf = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        if not csrf:
            return set()
        resp = session.post(
            "https://dnsdumpster.com/",
            data={"csrfmiddlewaretoken": csrf.group(1), "targetip": domain},
            timeout=30,
        )
        subs = set(re.findall(r">([\w.\-]+\." + re.escape(domain) + r")<", resp.text))
        log(f"  DNSDumpster → {len(subs)} 个子域名", "ok")
        return subs
    except Exception as e:
        log(f"  DNSDumpster 请求失败: {e}", "warn")
    return set()


def bufferover(domain):
    log("  查询 BufferOver.run...")
    try:
        resp = requests.get(
            f"https://dns.bufferover.run/dns?q=.{domain}",
            headers=HEADERS, timeout=30,
        )
        if resp.status_code == 200:
            subs = set()
            for record in resp.json().get("FDNS_A", []):
                parts = record.split(",")
                if len(parts) >= 2:
                    sub = parts[1].strip().lower()
                    if sub.endswith(f".{domain}"):
                        subs.add(sub)
            log(f"  BufferOver → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  BufferOver 请求失败: {e}", "warn")
    return set()


def collect_passive(domain):
    all_subs = set()
    collectors = [crt_sh, hackertarget, rapiddns, alienvault_otx, dnsdumpster, bufferover]
    for func in collectors:
        subs = func(domain)
        all_subs.update(subs)
    log(f"被动收集完成，共 {len(all_subs)} 个唯一子域名", "ok")
    return all_subs


# ── DNS 爆破 ─────────────────────────────────────────────────

def dns_resolve(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None


def brute_force_subdomains(domain, wordlist=None):
    words = wordlist or COMMON_SUBS
    log(f"  开始 DNS 爆破，测试 {len(words)} 个常见子域名...")
    found = {}

    def check(sub):
        full = f"{sub}.{domain}"
        ips = dns_resolve(full)
        return (full, ips) if ips else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(check, s): s for s in words}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found[result[0]] = result[1]

    log(f"  DNS 爆破发现 {len(found)} 个有效子域名", "ok")
    return found


# ── 主入口 ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="步骤1: 子域名收集")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    args = parser.parse_args()

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
        OUTPUT_DIR.mkdir(exist_ok=True)

    domain = args.domain.strip()
    if domain.startswith("http"):
        domain = re.sub(r"https?://", "", domain).rstrip("/")

    log(f"开始收集子域名: {domain}")
    log("=" * 50)

    # 被动收集
    all_subs = collect_passive(domain)

    # DNS 爆破
    brute = brute_force_subdomains(domain)
    for sub, ips in brute.items():
        if sub not in all_subs:
            all_subs.add(sub)

    # 保存结果（纯列表 + 详细）
    subdomains_list = sorted(all_subs)
    save_json(subdomains_list, f"{domain}_subdomains.json")

    subdomains_detail = {s: {"ips": brute.get(s, [])} for s in subdomains_list}
    save_json(subdomains_detail, f"{domain}_subdomains_detail.json")

    log(f"\n共收集到 {len(subdomains_list)} 个子域名")
    return subdomains_list


if __name__ == "__main__":
    main()
