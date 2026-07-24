#!/usr/bin/env python3
"""
SRC 资产收集流水线（资产收集专用，不含端口扫描/漏洞测试）

按照 8 步流程：
  1. 基础子域名收集 (crt.sh + Subfinder + OneForAll)
  2. 空间测绘补充 (FOFA / Hunter)
  3. 历史存档挖掘 (Wayback Machine)
  4. DNS 历史备案 (可选)
  5. JS 源码子域名提取
  6. DNS 解析 + IP 反查旁站 ★ 关键捡漏
  7. 汇总去重
  8. 存活探测 → live_targets.txt

用法：
  python3 engine/asset.py example.com                         # 完整收集
  python3 engine/asset.py example.com --quick                 # 快速模式（调步骤 2-4）
  python3 engine/asset.py example.com --no-js                 # 跳过 JS 提取
  python3 engine/asset.py example.com --no-reverse            # 跳过 IP 反查
  python3 engine/asset.py example.com --no-fofa               # 跳过 FOFA 测绘
"""
import argparse
import concurrent.futures
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import dns.resolver
import requests

from common import log, save_json, OUTPUT_DIR

requests.packages.urllib3.disable_warnings()


# ── 导入各模块的函数 ──────────────────────────────────────
# （import 放函数内是为了让 asset.py 能单独运行且不互相干扰）

def step1_collect(domain):
    """步骤 1：基础子域名收集"""
    log("=" * 30)
    log("【步骤 1】基础子域名收集 (crt.sh + Subfinder + OneForAll)")
    log("=" * 30)
    subs = set()

    # 从 collect.py 导入 passive 收集 + Subfinder + OneForAll
    try:
        import collect
        # 现有的 6 个 API 源
        subs.update(collect.collect_passive(domain))
        # DNS 爆破
        brute = collect.brute_force_subdomains(domain)
        for sub in brute:
            subs.add(sub)
    except Exception as e:
        log(f"  collect 模块出错: {e}", "warn")
        # 兜底：直接调用子函数
        try:
            for func_name in ["crt_sh", "hackertarget", "rapiddns",
                              "alienvault_otx", "dnsdumpster", "bufferover"]:
                try:
                    func = getattr(collect, func_name)
                    subs.update(func(domain))
                except Exception:
                    continue
        except Exception:
            log("  所有收集源均失败，使用空列表", "warn")

    log(f"步骤 1 完成: 已收集 {len(subs)} 个子域名", "ok")
    return subs


def step2_fofa(domain):
    """步骤 2：空间测绘补充 (FOFA)"""
    log("=" * 30)
    log("【步骤 2】空间测绘补充 (FOFA)")
    log("=" * 30)
    subs = set()

    try:
        from fofa import fofa_search, extract_domains_from_fofa

        # domain 搜索
        log("  搜索: domain=\"%s\"" % domain)
        results = fofa_search('domain="%s"' % domain)
        subs.update(extract_domains_from_fofa(results, domain))

        # cert 搜索
        log("  搜索: cert=\"%s\"" % domain)
        cert_results = fofa_search('cert="%s"' % domain)
        subs.update(extract_domains_from_fofa(cert_results, domain))

    except Exception as e:
        log(f"  FOFA 模块出错: {e}", "warn")

    if subs:
        save_json(sorted(subs), f"{domain}_fofa_subdomains.json")
    log(f"步骤 2 完成: FOFA 补充 {len(subs)} 个子域名", "ok")
    return subs


def step3_wayback(domain):
    """步骤 3：历史存档挖掘 (Wayback Machine)"""
    log("=" * 30)
    log("【步骤 3】历史存档挖掘 (Wayback Machine)")
    log("=" * 30)
    subs = set()

    try:
        import history
        wayback_data = history.fetch_wayback_urls(domain, limit=2000)
        subs.update(history.extract_wayback_subdomains(wayback_data, domain))
    except Exception as e:
        log(f"  Wayback 模块出错: {e}", "warn")

    if subs:
        save_json(sorted(subs), f"{domain}_wayback_subdomains.json")
    log(f"步骤 3 完成: Wayback 补充 {len(subs)} 个子域名", "ok")
    return subs


def step4_history(domain):
    """步骤 4：DNS 历史备案 (可选)"""
    log("=" * 30)
    log("【步骤 4】DNS 历史与备案")
    log("=" * 30)
    subs = set()

    try:
        import history
        dns_hist = history.query_dns_history(domain)
        # DNS 历史返回的是 IP 列表，不是域名，这步主要做备案
        history.query_icp(domain)
    except Exception as e:
        log(f"  DNS 历史查询出错: {e}", "warn")

    log("步骤 4 完成")
    return subs  # 这步基本不产生新子域名


def step5_js(domain, collected_subs, max_sites=10):
    """步骤 5：JS 源码子域名提取"""
    log("=" * 30)
    log("【步骤 5】JS 源码子域名提取")
    log("=" * 30)
    subs = set()

    # 选前 N 个域名做快速存活探测
    candidates = list(collected_subs)[:max_sites * 3]
    probe_list = []

    # 快速探测哪些存活
    for sub in candidates:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{sub}"
            try:
                r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5, verify=False)
                if r.status_code < 400 or r.status_code in (401, 403):
                    probe_list.append(url)
                    break
            except Exception:
                continue
        if len(probe_list) >= max_sites:
            break

    log(f"  存活站点 {len(probe_list)} 个，开始 JS 提取...")

    # 对每个存活站点分析 JS
    import httpprobe
    for url in probe_list:
        try:
            js_results = httpprobe.analyze_js(url, main_domain=domain)
            for d in js_results.get("subdomains", []):
                if d.endswith(f".{domain}") and "*" not in d:
                    subs.add(d)
        except Exception as e:
            log(f"  JS 分析 {url} 失败: {e}", "debug")

    if subs:
        save_json(sorted(subs), f"{domain}_js_subdomains.json")
    log(f"步骤 5 完成: JS 提取 {len(subs)} 个子域名", "ok")
    return subs


def step6_resolve_and_reverse(domain, collected_subs, max_ips=30):
    """步骤 6：DNS 解析 + IP 反查旁站"""
    log("=" * 30)
    log("【步骤 6】DNS 解析 + IP 反查旁站 ★")
    log("=" * 30)
    new_subs = set()

    # DNS 批量解析
    log("  批量 DNS 解析...")
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {}
        for sub in collected_subs:
            futures[pool.submit(_resolve_one, sub)] = sub
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                ips = future.result()
                if ips:
                    resolved[sub] = ips
            except Exception:
                pass

    all_ips = set()
    for ips in resolved.values():
        all_ips.update(ips)
    log(f"  解析完成: {len(resolved)} 个有效, {len(all_ips)} 个 IP")

    if resolved:
        save_json({s: {"ips": ips} for s, ips in resolved.items()}, f"{domain}_resolved.json")
        save_json(sorted(all_ips), f"{domain}_ips.json")

    # IP 反查旁站（只查前 max_ips 个，避免太多请求）
    log("  IP 反查旁站...")
    # 优先查有最多域名的 IP（可能是一台重要的服务器）
    ip_counter = Counter()
    for ips in resolved.values():
        ip_counter.update(ips)

    top_ips = [ip for ip, _ in ip_counter.most_common(max_ips)]
    log(f"  对 {len(top_ips)} 个 IP 进行反查...")

    try:
        from fofa import ip_reverse_lookup
        reverse_result = ip_reverse_lookup(top_ips, engine="fofa")

        # 提取属于主域名的旁站
        for ip, domains in reverse_result.items():
            for d in domains:
                d = d.strip().lower()
                if d.endswith(f".{domain}") and "*" not in d and d != domain:
                    new_subs.add(d)
    except Exception as e:
        log(f"  IP 反查出错: {e}", "warn")

    if new_subs:
        save_json(sorted(new_subs), f"{domain}_reverse_subdomains.json")
    log(f"步骤 6 完成: 旁站补充 {len(new_subs)} 个子域名", "ok")
    return new_subs


def _resolve_one(sub):
    """辅助：解析单个域名"""
    try:
        answers = dns.resolver.resolve(sub, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def step7_merge(domain, *sub_sets):
    """步骤 7：汇总去重"""
    log("=" * 30)
    log("【步骤 7】汇总去重")
    log("=" * 30)

    all_subs = set()
    for s in sub_sets:
        all_subs.update(s)

    # 过滤：必须是目标域名的子域名
    final = set()
    for sub in all_subs:
        sub = sub.strip().lower()
        if sub.endswith(f".{domain}") and "*" not in sub and sub != domain:
            final.add(sub)

    result = sorted(final)
    save_json(result, f"{domain}_all_assets.json")
    log(f"步骤 7 完成: 去重后共 {len(result)} 个资产", "ok")
    return result


def step8_alive(domain, subdomains):
    """步骤 8：存活探测 → live_targets.txt"""
    log("=" * 30)
    log("【步骤 8】存活探测")
    log("=" * 30)

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {}
        for sub in subdomains:
            futures[pool.submit(_probe_one, sub)] = sub
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                result = future.result()
                if result:
                    alive.append(result)
            except Exception:
                pass

    # 按状态码排序
    alive.sort(key=lambda x: (x.get("status", 999), x.get("url", "")))

    # 保存 JSON
    save_json(alive, f"{domain}_live.json")

    # 保存纯文本列表
    live_path = OUTPUT_DIR / f"{domain}_live_targets.txt"
    with open(live_path, "w", encoding="utf-8") as f:
        for entry in alive:
            url = entry.get("url", "")
            status = entry.get("status", 0)
            title = entry.get("title", "")
            f.write(f"{url} [{status}] {title}\n")

    # 也保存一个纯 URL 列表（方便喂给扫描器）
    url_only_path = OUTPUT_DIR / f"{domain}_live_urls.txt"
    with open(url_only_path, "w", encoding="utf-8") as f:
        for entry in alive:
            f.write(entry.get("url", "") + "\n")

    log(f"步骤 8 完成: {len(alive)} 个存活站点", "ok")
    log(f"  存活清单: {live_path.name}", "ok")
    log(f"  URL 列表: {url_only_path.name}", "ok")
    return alive


def _probe_one(sub):
    """辅助：单域名存活探测"""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                             timeout=8, verify=False, allow_redirects=True)
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:5000], re.I | re.S)
            if m:
                title = m.group(1).strip()[:80]
            return {
                "subdomain": sub,
                "url": r.url,
                "status": r.status_code,
                "title": title,
                "server": r.headers.get("Server", ""),
            }
        except Exception:
            continue
    return None


# ── 主流程 ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SRC 资产收集流水线 — 8 步完整资产收集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 engine/asset.py example.com             # 完整 8 步\n"
            "  python3 engine/asset.py example.com --quick     # 跳过 FOFA + JS + 反查\n"
            "  python3 engine/asset.py example.com --no-fofa   # 只跳过 FOFA\n"
            "  python3 engine/asset.py example.com --no-js     # 只跳过 JS\n"
        ),
    )
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("--quick", action="store_true", help="快速模式（跳过 FOFA/JS/反查）")
    parser.add_argument("--no-fofa", action="store_true", help="跳过 FOFA 测绘")
    parser.add_argument("--no-js", action="store_true", help="跳过 JS 子域名提取")
    parser.add_argument("--no-reverse", action="store_true", help="跳过 IP 反查旁站")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    args = parser.parse_args()

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
    OUTPUT_DIR.mkdir(exist_ok=True)

    domain = args.domain.strip().lower()
    if domain.startswith("http"):
        domain = re.sub(r"https?://", "", domain).rstrip("/")

    log("=" * 50)
    log("SRC 资产收集流水线")
    log("目标: %s" % domain)
    log("模式: %s" % ("快速" if args.quick else "完整"))
    log("=" * 50)

    start = time.time()

    # 执行各步骤，累计资产
    all_subsets = {}

    # 步骤 1：基础子域名收集（必做）
    s1 = step1_collect(domain)
    all_subsets["01_collect"] = s1

    # 步骤 2：FOFA（可选跳过）
    if not args.quick and not args.no_fofa:
        s2 = step2_fofa(domain)
        all_subsets["02_fofa"] = s2
    else:
        all_subsets["02_fofa"] = set()

    # 步骤 3：Wayback（必做）
    s3 = step3_wayback(domain)
    all_subsets["03_wayback"] = s3

    # 步骤 4：DNS 历史（轻量，必做）
    s4 = step4_history(domain)
    all_subsets["04_history"] = s4

    # 临时合并，用于 JS 和 反查
    temp_all = set()
    for s in all_subsets.values():
        temp_all.update(s)
    log("临时汇总: %d 个子域名（JS/反查用）" % len(temp_all))

    # 步骤 5：JS 提取（可选跳过）
    if not args.quick and not args.no_js:
        s5 = step5_js(domain, temp_all, max_sites=10)
        all_subsets["05_js"] = s5
    else:
        all_subsets["05_js"] = set()

    # 重新合并（加入 JS 结果后）
    temp_all = set()
    for s in all_subsets.values():
        temp_all.update(s)

    # 步骤 6：DNS 解析 + IP 反查（可选跳过反查部分）
    if not args.quick and not args.no_reverse:
        s6 = step6_resolve_and_reverse(domain, temp_all, max_ips=30)
        all_subsets["06_reverse"] = s6
    else:
        # 没有反查也做 DNS 解析
        log("【步骤 6】DNS 解析（跳过反查）")
        s6 = step6_resolve_and_reverse(domain, temp_all, max_ips=0)
        all_subsets["06_reverse"] = set()

    # 步骤 7：汇总去重
    final_subs = step7_merge(domain, *all_subsets.values())

    # 步骤 8：存活探测
    alive = step8_alive(domain, final_subs)

    # 来源统计
    log("=" * 50)
    log("资产收集完成")
    for name, sub_set in sorted(all_subsets.items()):
        log("  %s: %d" % (name, len(sub_set)))
    log("  去重汇总: %d" % len(final_subs))
    log("  存活站点: %d" % len(alive))
    log("  耗时: %.1f 秒" % (time.time() - start))
    log("=" * 50)
    log("最终输出文件:")
    log("  %s/%s_all_assets.json   — 全部资产" % (OUTPUT_DIR.name, domain))
    log("  %s/%s_live_targets.txt  — 存活清单（带状态码/标题）" % (OUTPUT_DIR.name, domain))
    log("  %s/%s_live_urls.txt     — URL 纯列表（喂给扫描器）" % (OUTPUT_DIR.name, domain))


if __name__ == "__main__":
    main()
