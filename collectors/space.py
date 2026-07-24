#!/usr/bin/env python3
"""
空间测绘模块 — FOFA / Hunter API 查询 + IP 反查旁站

功能：
  1. FOFA 搜索：domain="target.com" / cert="target.com"
  2. FOFA IP 反查：ip="x.x.x.x" （旁站发现）
  3. Hunter 搜索（FOFA 不可用时的备选）
  4. 输出查到的子域名、IP、标题、技术栈

用法：
  python3 fofa.py domain example.com       # 域名搜索
  python3 fofa.py ip 1.2.3.4               # IP 反查旁站
  python3 fofa.py --list                   # 可用的搜索模式

配置：
  在 config.json 中填写：
    "fofa_email": "your@email.com",
    "fofa_key": "your_fofa_api_key",
    "hunter_key": "your_hunter_api_key"
"""
import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.utils import log, save_json, load_config, HEADERS

requests.packages.urllib3.disable_warnings()


# ── FOFA API ─────────────────────────────────────────────────

FOFA_BASE = "https://fofa.info/api/v1/search/all"

def fofa_search(query, fields="domain,host,ip,title", size=10000, email="", key=""):
    """
    FOFA API v1 搜索

    参数:
        query:  FOFA 搜索语法，如 domain="example.com"
        fields: 返回字段
        size:   结果数量上限
        email/key: API 凭证（不传则从 config.json 读取）

    返回:
        [{"domain","host","ip","title",...}, ...]
    """
    if not email or not key:
        cfg = load_config()
        if cfg:
            email = cfg.get("fofa_email", email)
            key = cfg.get("fofa_key", key)

    if not email or not key:
        log("FOFA API 未配置（config.json 中的 fofa_email/fofa_key）", "warn")
        return []

    try:
        qb64 = base64.b64encode(query.encode()).decode()
        resp = requests.get(
            FOFA_BASE,
            params={"key": key, "qbase64": qb64, "fields": fields, "size": size},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("error"):
                log(f"FOFA 查询失败: {data.get('errmsg', 'unknown')}", "warn")
                return []
            results = data.get("results", [])
            # results 是列表的列表，每个子列表对应 fields 顺序
            field_list = fields.split(",")
            parsed = []
            for row in results:
                entry = {}
                for i, f in enumerate(field_list):
                    if i < len(row):
                        entry[f.strip()] = row[i]
                parsed.append(entry)
            log(f"  FOFA → {len(parsed)} 条结果", "ok")
            return parsed
        else:
            log(f"FOFA 请求失败: HTTP {resp.status_code}", "warn")
    except Exception as e:
        log(f"FOFA 查询出错: {e}", "warn")
    return []


# ── Hunter（鹰图）API ────────────────────────────────────────

HUNTER_BASE = "https://hunter.qianxin.com/openApi/search"

def hunter_search(domain, key=""):
    """
    Hunter 域名搜索（FOFA 备选）

    参数:
        domain: 目标域名
        key:    API Key（不传则从 config.json 读取）
    """
    if not key:
        cfg = load_config()
        if cfg:
            key = cfg.get("hunter_key", "")

    if not key:
        log("Hunter API 未配置", "warn")
        return []

    results = []
    try:
        for page in range(1, 4):  # 最多翻 3 页
            resp = requests.get(
                HUNTER_BASE,
                params={
                    "api-key": key,
                    "search": f'domain.suffix="{domain}"',
                    "page": page,
                    "page_size": 100,
                    "is_web": 1,
                    "start_time": "2024-01-01",
                    "end_time": time.strftime("%Y-%m-%d"),
                },
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") != 200:
                    break
                items = data.get("data", {}).get("arr", [])
                if not items:
                    break
                for item in items:
                    results.append({
                        "domain": item.get("domain", ""),
                        "host": item.get("url", ""),
                        "ip": item.get("ip", ""),
                        "title": item.get("title", ""),
                        "source": "hunter",
                    })
                if len(items) < 100:
                    break
                time.sleep(0.5)  # 限速
            else:
                break
        log(f"  Hunter → {len(results)} 条结果", "ok")
    except Exception as e:
        log(f"Hunter 查询出错: {e}", "warn")
    return results


# ── IP 反查旁站 ──────────────────────────────────────────────

def ip_reverse_lookup(ip_list, engine="fofa"):
    """
    IP 反查：对 IP 列表查询同 IP 上托管了哪些域名

    参数:
        ip_list: IP 地址列表
        engine:  "fofa" 或 "hunter"

    返回: {ip: [域名列表]}
    """
    if isinstance(ip_list, str):
        ip_list = [ip_list]

    result = {}
    for ip in ip_list:
        ip = ip.strip()
        if not ip:
            continue
        log(f"  反查旁站: {ip}")
        try:
            if engine == "fofa":
                entries = fofa_search(f'ip="{ip}"', fields="domain,host", size=100)
                domains = set()
                for e in entries:
                    d = e.get("domain", "").strip().lower()
                    if d:
                        domains.add(d)
                if domains:
                    result[ip] = sorted(domains)
                    log(f"    {ip} → {len(domains)} 个旁站域名", "ok")
                else:
                    log(f"    {ip} → 无旁站结果", "info")
            elif engine == "hunter":
                # Hunter 不太方便直接 IP 查，标记 TODO
                log(f"    Hunter 暂不支持直接 IP 反查，跳过", "warn")
        except Exception as e:
            log(f"    {ip} 反查出错: {e}", "warn")

    # 统计
    total_sites = sum(len(v) for v in result.values())
    log(f"IP 反查完成: {len(result)} 个 IP 有旁站, 共 {total_sites} 个域名", "ok")
    return result


# ── 工具 ─────────────────────────────────────────────────────

def extract_domains_from_fofa(entries, main_domain):
    """从 FOFA/Hunter 结果中提取属于主域名的子域名"""
    subs = set()
    for e in entries:
        for key in ("domain", "host"):
            val = e.get(key, "").strip().lower()
            if not val:
                continue
            # 从 URL 中提取域名
            if val.startswith("http"):
                from urllib.parse import urlparse
                val = urlparse(val).hostname or val
            # 移除端口
            if ":" in val and val.count(".") >= 1:
                val = val.split(":")[0]
            if val.endswith(f".{main_domain}") or val == main_domain:
                if "*" not in val and val != main_domain:
                    subs.add(val)
    return subs


def extract_domains_from_ip_reverse(reverse_result, main_domain):
    """从 IP 反查结果中提取属于主域名的域名"""
    domains = set()
    for ip, domain_list in reverse_result.items():
        for d in domain_list:
            d = d.strip().lower()
            if d.endswith(f".{main_domain}") and "*" not in d and d != main_domain:
                domains.add(d)
    return domains


# ── 主入口 ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="空间测绘模块 — FOFA / Hunter / IP 反查")
    parser.add_argument("mode", choices=["domain", "ip", "cert"], help="查询模式")
    parser.add_argument("target", help="目标（域名或 IP）")
    parser.add_argument("--engine", choices=["fofa", "hunter"], default="fofa", help="查询引擎")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    args = parser.parse_args()

    if args.output:
        global OUTPUT_DIR
        from common.utils import OUTPUT_DIR as _OD
        OUTPUT_DIR = Path(args.output)
    from common.utils import OUTPUT_DIR

    target = args.target.strip().lower()

    if args.mode == "domain":
        log(f"FOFA 查询: domain=\"{target}\"")
        results = fofa_search(f'domain="{target}"')
        subs = extract_domains_from_fofa(results, target)
        if subs:
            save_json(sorted(subs), f"{target}_fofa_domains.json")
        # 也查 cert
        log(f"FOFA 查询: cert=\"{target}\"")
        cert_results = fofa_search(f'cert="{target}"')
        cert_subs = extract_domains_from_fofa(cert_results, target)
        subs.update(cert_subs)
        if subs:
            save_json(sorted(subs), f"{target}_fofa_subdomains.json")
            log(f"FOFA 测绘完成: 共 {len(subs)} 个子域名")

    elif args.mode == "ip":
        log(f"IP 反查: {target}")
        result = ip_reverse_lookup([target], engine=args.engine)
        all_domains = set()
        for ip, domains in result.items():
            all_domains.update(domains)
        if all_domains:
            save_json({
                "ip": target,
                "total": len(all_domains),
                "domains": sorted(all_domains),
            }, f"reverse_{target.replace('.', '_')}.json")
            log(f"IP 反查完成: {len(all_domains)} 个域名")

    elif args.mode == "cert":
        log(f"FOFA cert 查询: cert=\"{target}\"")
        results = fofa_search(f'cert="{target}"')
        subs = extract_domains_from_fofa(results, target)
        if subs:
            save_json(sorted(subs), f"{target}_cert_subdomains.json")
            log(f"证书搜索完成: {len(subs)} 个子域名")


if __name__ == "__main__":
    main()
