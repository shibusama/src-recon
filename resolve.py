#!/usr/bin/env python3
"""
步骤 2：DNS 解析 + ASN 查询 解析子域名 A 记录，查询 IP 归属组织

用法：
  python3 resolve.py example.com
  python3 resolve.py example.com -i results/example_com_subdomains_detail.json
"""
import argparse
import concurrent.futures
import ipaddress
import sys
from pathlib import Path

import dns.resolver
import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import log, save_json, load_json, HEADERS, OUTPUT_DIR


requests.packages.urllib3.disable_warnings()


def resolve_domain(domain, rtype="A"):
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def resolve_all(subdomains, max_workers=50):
    log(f"  开始 DNS 解析验证 {len(subdomains)} 个子域名...")
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(resolve_domain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                ips = future.result()
                if ips:
                    resolved[sub] = ips
            except Exception:
                pass
    log(f"  DNS 解析完成，{len(resolved)} 个有效", "ok")
    return resolved


def get_all_ips(resolved):
    ips = set()
    for sub, ip_list in resolved.items():
        for ip in ip_list:
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except ValueError:
                pass
    return ips


def get_asn_info(ip):
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip": ip,
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "country": data.get("country", ""),
                "city": data.get("city", ""),
            }
    except Exception:
        pass
    return None


def collect_asn_info(ips, max_workers=10):
    log("  查询 IP 的 ASN / 组织信息...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(get_asn_info, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass
    log(f"  ASN 查询完成，{len(results)} 个有结果", "ok")
    return results


def main():
    parser = argparse.ArgumentParser(description="步骤2: DNS 解析 + ASN 查询")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("-i", "--input", help="子域名文件（默认 results/{domain}_subdomains_detail.json）")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    args = parser.parse_args()

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
        OUTPUT_DIR.mkdir(exist_ok=True)

    domain = args.domain.strip()
    if domain.startswith("http"):
        import re
        domain = re.sub(r"https?://", "", domain).rstrip("/")

    # 读取子域名列表
    sub_file = args.input or f"{domain}_subdomains_detail.json"
    data = load_json(sub_file)
    if data is None:
        log(f"请先运行 collect.py {domain}", "err")
        return

    subdomains = list(data.keys())
    log(f"读取到 {len(subdomains)} 个子域名")
    log("=" * 50)

    # 解析
    resolved = resolve_all(subdomains)
    all_ips = get_all_ips(resolved)
    log(f"收集到 {len(all_ips)} 个唯一 IP", "ok")

    # 保存
    save_json({s: {"ips": ips} for s, ips in sorted(resolved.items())}, f"{domain}_resolved.json")
    save_json(sorted(all_ips), f"{domain}_ips.json")

    # ASN
    asn_info = collect_asn_info(all_ips, 10)
    save_json(asn_info, f"{domain}_asn.json")

    log(f"\nDNS 解析完成: {len(resolved)} 个有效, {len(all_ips)} 个唯一 IP")


if __name__ == "__main__":
    main()
