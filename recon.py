#!/usr/bin/env python3
"""lenovo.com 资产收集工具 - 子域名枚举 + HTTP 探测"""

import asyncio
import concurrent.futures
import json
import re
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path

import dns.resolver
import requests

DOMAIN = "lenovo.com"
OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_DIR.mkdir(exist_ok=True)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── 1. 被动子域名收集 ──────────────────────────────────────

def crt_sh(domain):
    """从 crt.sh 证书透明度日志获取子域名"""
    log("查询 crt.sh 证书透明度日志...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(f".{domain}") and "*" not in n:
                        subs.add(n)
            log(f"  crt.sh 发现 {len(subs)} 个子域名")
            return subs
    except Exception as e:
        log(f"  crt.sh 查询失败: {e}")
    return set()


def hackertarget(domain):
    """从 HackerTarget 获取子域名"""
    log("查询 HackerTarget...")
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            subs = set()
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if parts and "." in parts[0] and parts[0].endswith(f".{domain}"):
                    subs.add(parts[0].strip().lower())
            log(f"  HackerTarget 发现 {len(subs)} 个子域名")
            return subs
    except Exception as e:
        log(f"  HackerTarget 查询失败: {e}")
    return set()


def rapiddns(domain):
    """从 RapidDNS 获取子域名"""
    log("查询 RapidDNS...")
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            subs = set()
            for m in re.findall(r'>([\w\.\-]+\.' + re.escape(domain) + r')<', resp.text):
                subs.add(m.lower())
            log(f"  RapidDNS 发现 {len(subs)} 个子域名")
            return subs
    except Exception as e:
        log(f"  RapidDNS 查询失败: {e}")
    return set()


def alienvault_otx(domain):
    """从 AlienVault OTX 获取子域名"""
    log("查询 AlienVault OTX...")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(f".{domain}") and "*" not in hostname:
                    subs.add(hostname)
            log(f"  AlienVault OTX 发现 {len(subs)} 个子域名")
            return subs
    except Exception as e:
        log(f"  AlienVault OTX 查询失败: {e}")
    return set()


def dnsdumpster(domain):
    """从 DNSDumpster 获取子域名"""
    log("查询 DNSDumpster...")
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        # 获取 CSRF token
        resp = session.get("https://dnsdumpster.com/", timeout=15)
        csrf = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        if not csrf:
            return set()
        token = csrf.group(1)
        resp = session.post(
            "https://dnsdumpster.com/",
            data={"csrfmiddlewaretoken": token, "targetip": domain},
            timeout=30,
        )
        subs = set()
        for m in re.findall(r'>([\w\.\-]+\.' + re.escape(domain) + r')<', resp.text):
            subs.add(m.lower())
        log(f"  DNSDumpster 发现 {len(subs)} 个子域名")
        return subs
    except Exception as e:
        log(f"  DNSDumpster 查询失败: {e}")
    return set()


def bufferover(domain):
    """从 BufferOver.run 获取子域名"""
    log("查询 BufferOver.run...")
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        resp = requests.get(url, headers={**HEADERS, "x-api-key": ""}, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for record in data.get("FDNS_A", []):
                parts = record.split(",")
                if len(parts) >= 2:
                    sub = parts[1].strip().lower()
                    if sub.endswith(f".{domain}"):
                        subs.add(sub)
            log(f"  BufferOver 发现 {len(subs)} 个子域名")
            return subs
    except Exception as e:
        log(f"  BufferOver 查询失败: {e}")
    return set()


# ── 2. 主动 DNS 爆破 ──────────────────────────────────────

COMMON_SUBS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "demo", "app", "web", "portal", "login", "auth", "sso",
    "vpn", "remote", "owa", "exchange", "mail2", "smtp", "pop", "imap",
    "ns1", "ns2", "dns", "dns1", "dns2", "cdn", "static", "assets",
    "img", "images", "media", "video", "stream", "live", "news",
    "blog", "shop", "store", "cart", "checkout", "payment", "pay",
    "support", "help", "kb", "wiki", "docs", "forum", "community",
    "cloud", "aws", "azure", "gcp", "server", "db", "database", "mysql",
    "redis", "cache", "proxy", "gateway", "lb", "loadbalancer",
    "internal", "intranet", "corp", "corpnet", "office", "hr",
    "finance", "erp", "crm", "oa", "bi", "analytics", "monitor",
    "jenkins", "git", "github", "gitlab", "ci", "cd", "build",
    "m", "mobile", "ios", "android", "apk",
    "partner", "affiliate", "reseller", "dealer",
    "training", "learn", "edu", "academy", "event", "events",
    "careers", "job", "jobs", "recruit",
    "security", "sec", "soc", "cert",
    "iot", "smart", "ai", "ml", "data",
    "us", "cn", "eu", "asia", "ap", "jp", "kr", "tw", "hk", "sg",
    "lenovo", "thinkpad", "thinkcentre", "thinkstation", "yoga",
    "legion", "ideapad", "mot", "motorola", "moto",
    "vibe", "zuk", "zukz", "zukz2",
]


def dns_resolve(subdomain):
    """尝试解析子域名"""
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        ips = [str(rdata) for rdata in answers]
        return ips
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None


def brute_force_subdomains(domain, subs):
    """DNS 爆破子域名"""
    log(f"开始 DNS 爆破，测试 {len(subs)} 个常见子域名...")
    found = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {}
        for sub in subs:
            full = f"{sub}.{domain}"
            futures[pool.submit(dns_resolve, full)] = full

        for future in concurrent.futures.as_completed(futures):
            full = futures[future]
            try:
                ips = future.result()
                if ips:
                    found[full] = ips
            except Exception:
                pass

    log(f"  DNS 爆破发现 {len(found)} 个有效子域名")
    return found


# ── 3. HTTP 探测 ──────────────────────────────────────────

def http_probe(subdomains, max_workers=50):
    """HTTP 探测子域名"""
    log(f"开始 HTTP 探测 {len(subdomains)} 个子域名...")
    results = []

    def probe(sub):
        urls = [f"https://{sub}", f"http://{sub}"]
        for url in urls:
            try:
                resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True, verify=False)
                return {
                    "subdomain": sub,
                    "url": resp.url,
                    "status": resp.status_code,
                    "title": re.sub(r'<[^>]+>', '', resp.text[:500]).strip()[:100],
                    "server": resp.headers.get("Server", ""),
                    "tech": [],
                }
            except requests.exceptions.SSLError:
                continue
            except Exception:
                continue
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass

    log(f"  HTTP 探测完成，{len(results)} 个可访问")
    return results


# ── 4. 主流程 ─────────────────────────────────────────────

def main():
    domain = DOMAIN
    if len(sys.argv) > 1:
        domain = sys.argv[1]

    log(f"开始收集 {domain} 资产...")
    start = time.time()

    # 被动收集
    all_subs = set()
    for func in [crt_sh, hackertarget, rapiddns, alienvault_otx, bufferover]:
        subs = func(domain)
        all_subs.update(subs)

    log(f"被动收集共发现 {len(all_subs)} 个唯一子域名")

    # DNS 解析验证
    log("开始 DNS 解析验证...")
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(dns_resolve, sub): sub for sub in all_subs}
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                ips = future.result()
                if ips:
                    resolved[sub] = ips
            except Exception:
                pass

    log(f"DNS 解析验证通过 {len(resolved)} 个子域名")

    # DNS 爆破
    brute_found = brute_force_subdomains(domain, COMMON_SUBS)
    for sub, ips in brute_found.items():
        if sub not in resolved:
            resolved[sub] = ips

    # 保存子域名结果
    subs_file = OUTPUT_DIR / f"{domain}_subdomains.json"
    subs_data = {sub: {"ips": ips} for sub, ips in sorted(resolved.items())}
    with open(subs_file, "w") as f:
        json.dump(subs_data, f, indent=2, ensure_ascii=False)
    log(f"子域名结果已保存: {subs_file}")

    # HTTP 探测
    http_results = http_probe(list(resolved.keys()))

    # 保存 HTTP 结果
    http_file = OUTPUT_DIR / f"{domain}_http.json"
    with open(http_file, "w") as f:
        json.dump(http_results, f, indent=2, ensure_ascii=False)
    log(f"HTTP 结果已保存: {http_file}")

    # 生成摘要报告
    report_file = OUTPUT_DIR / f"{domain}_report.txt"
    with open(report_file, "w") as f:
        f.write(f"lenovo.com 资产收集报告\n")
        f.write(f"{'='*60}\n")
        f.write(f"收集时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总子域名数: {len(resolved)}\n")
        f.write(f"HTTP 可访问: {len(http_results)}\n\n")

        f.write("--- 子域名列表 ---\n")
        for sub in sorted(resolved.keys()):
            ips = ", ".join(resolved[sub])
            f.write(f"  {sub} -> {ips}\n")

        f.write(f"\n--- HTTP 服务 ---\n")
        for r in sorted(http_results, key=lambda x: x["status"]):
            f.write(f"  [{r['status']}] {r['url']}")
            if r["title"]:
                f.write(f"  | {r['title']}")
            if r["server"]:
                f.write(f"  | Server: {r['server']}")
            f.write("\n")

        # 按状态码统计
        status_counts = defaultdict(int)
        for r in http_results:
            status_counts[r["status"]] += 1
        f.write(f"\n--- 状态码统计 ---\n")
        for code in sorted(status_counts.keys()):
            f.write(f"  {code}: {status_counts[code]} 个\n")

    log(f"报告已保存: {report_file}")
    elapsed = time.time() - start
    log(f"完成！耗时 {elapsed:.1f} 秒")

    # 打印摘要
    print(f"\n{'='*60}")
    print(f"收集完成摘要:")
    print(f"  总子域名: {len(resolved)}")
    print(f"  HTTP 可访问: {len(http_results)}")
    print(f"  结果目录: {OUTPUT_DIR}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
