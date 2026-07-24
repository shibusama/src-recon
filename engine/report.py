#!/usr/bin/env python3
"""
步骤 6：报告生成 — 汇总所有 JSON，生成 TXT + HTML 报告

用法：
  python3 report.py example.com
  python3 report.py example.com --quick （快速模式，只含子域名 + HTTP）
"""
import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import log, load_json, OUTPUT_DIR


def generate_txt_report(domain, resolved, all_ips, asn_info, open_ports,
                        services, http_results, quick=False):
    suffix = "_quick_report.txt" if quick else "_full_report.txt"
    report_file = OUTPUT_DIR / f"{domain}{suffix}"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"{'=' * 70}\n")
        f.write(f"  {domain} 资产收集报告\n")
        f.write(f"{'=' * 70}\n")
        f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("摘要:\n")
        f.write(f"  子域名总数: {len(resolved)}\n")
        f.write(f"  唯一 IP 数: {len(all_ips)}\n")
        if not quick:
            f.write(f"  开放端口数: {sum(len(v) for v in open_ports.values())}\n")
        f.write(f"  HTTP 可访问: {len(http_results)}\n\n")

        if asn_info:
            f.write("ASN / 组织分布:\n")
            orgs = defaultdict(list)
            for info in asn_info:
                orgs[info.get("org", "Unknown")].append(info["ip"])
            for org, ips in sorted(orgs.items(), key=lambda x: -len(x[1])):
                f.write(f"  {org}: {len(ips)} 个 IP\n")
                for ip in sorted(ips)[:3]:
                    f.write(f"    - {ip}\n")
                if len(ips) > 3:
                    f.write(f"    ... 还有 {len(ips) - 3} 个\n")
            f.write("\n")

        f.write(f"子域名列表 ({len(resolved)} 个):\n")
        for sub in sorted(resolved.keys()):
            ips = ", ".join(resolved[sub].get("ips", resolved[sub]) if isinstance(resolved[sub], dict) else [resolved[sub]]) if isinstance(resolved[sub], list) else resolved[sub]
            f.write(f"  {sub} -> {ips}\n")
        f.write("\n")

        if not quick and open_ports:
            f.write("开放端口:\n")
            for ip in sorted(open_ports.keys()):
                ports = ", ".join(str(p) for p in sorted(open_ports[ip]))
                f.write(f"  {ip}: {ports}\n")
            f.write("\n")

        if not quick and services:
            f.write("服务识别:\n")
            for svc in sorted(services, key=lambda x: (x["ip"], x["port"])):
                ssl_tag = " [SSL]" if svc.get("ssl") else ""
                banner = svc.get("banner", "")[:80].replace("\n", " ").replace("\r", "")
                f.write(f"  {svc['ip']}:{svc['port']} -> {svc.get('service', '?')}{ssl_tag} | {banner}\n")
            f.write("\n")

        f.write("HTTP 服务:\n")
        status_counts = defaultdict(int)
        for r in http_results:
            status_counts[r["status"]] += 1
        f.write("  状态码分布: ")
        f.write(", ".join(f"{code}: {count}个" for code, count in sorted(status_counts.items())))
        f.write("\n\n")
        for r in sorted(http_results, key=lambda x: x["status"]):
            url = r.get("url") or r.get("subdomain", "")
            title = (r.get("title") or "")[:60]
            tech = ", ".join(r.get("tech", []))
            f.write(f"  [{r['status']}] {url}")
            if title:
                f.write(f"  | {title}")
            if tech:
                f.write(f"  | {tech}")
            f.write("\n")

    log(f"报告已保存: {report_file}", "ok")
    return report_file


def generate_html_report(domain, resolved, all_ips, asn_info, open_ports,
                         services, http_results, quick=False):
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    status_counts = defaultdict(int)
    for r in http_results:
        status_counts[r["status"]] += 1

    rows_html = ""
    for r in sorted(http_results, key=lambda x: x["status"]):
        url = r.get("url") or r.get("subdomain", "")
        title = (r.get("title") or "")[:60]
        server = (r.get("server") or "")[:30]
        tech = ", ".join(r.get("tech", []))
        waf = ", ".join(r.get("waf", []))
        color = "#22c55e" if r["status"] < 300 else "#eab308" if r["status"] < 400 else "#ef4444"
        rows_html += f"<tr><td><span class='status' style='background:{color}'>{r['status']}</span></td><td><a href='{url}' target='_blank'>{url[:70]}</a></td><td>{title}</td><td>{server}</td><td>{tech}</td><td>{waf}</td></tr>\n"

    subs_html = ""
    for sub in sorted(resolved.keys()):
        raw = resolved[sub]
        if isinstance(raw, dict):
            ips_str = ", ".join(raw.get("ips", []))
        elif isinstance(raw, list):
            ips_str = ", ".join(raw)
        else:
            ips_str = str(raw)
        subs_html += f"<tr><td>{sub}</td><td>{ips_str}</td></tr>\n"

    status_dist = "".join(
        f"<span class='sub-status' style='background:{'#22c55e' if c < 300 else '#eab308' if c < 400 else '#ef4444'}'>{c}: {status_counts[c]}</span> "
        for c in sorted(status_counts.keys())
    )

    total_open = sum(len(v) for v in open_ports.values()) if open_ports else 0
    errors = sum(c for c in status_counts.values() if c >= 400)

    # 状态码分布 bar
    total_hits = sum(status_counts.values()) or 1
    bar_html = ""
    colors = {"200": "#22c55e", "3xx": "#eab308", "4xx": "#f97316", "5xx": "#ef4444"}
    for label, codes, color in [("2xx", [c for c in status_counts if c < 300], "#22c55e"),
                                 ("3xx", [c for c in status_counts if 300 <= c < 400], "#eab308"),
                                 ("4xx", [c for c in status_counts if 400 <= c < 500], "#f97316"),
                                 ("5xx", [c for c in status_counts if c >= 500], "#ef4444")]:
        count = sum(status_counts[c] for c in codes)
        pct = count * 100 / total_hits
        if count:
            bar_html += f"<div style='flex:{pct};background:{color};text-align:center;color:#fff;font-size:12px;padding:4px 0;'>{label} {count}</div>"

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{domain} - 资产报告</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;}}
.container{{max-width:1200px;margin:0 auto;padding:20px;}}
.header{{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid #334155;padding:30px 0;margin-bottom:30px;}}
.header h1{{font-size:28px;color:#f8fafc;}}
.header .meta{{color:#94a3b8;margin-top:8px;font-size:14px;}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:30px;}}
.stat-card{{background:#1e293b;border-radius:12px;padding:20px;text-align:center;border:1px solid #334155;}}
.stat-card .num{{font-size:32px;font-weight:700;color:#3b82f6;}}
.stat-card .label{{font-size:13px;color:#94a3b8;margin-top:4px;}}
.stat-card.green .num{{color:#22c55e;}}
.stat-card.yellow .num{{color:#eab308;}}
.stat-card.red .num{{color:#ef4444;}}
h2{{font-size:20px;margin:24px 0 12px;color:#f1f5f9;border-left:4px solid #3b82f6;padding-left:12px;}}
table{{width:100%;border-collapse:collapse;margin-bottom:24px;background:#1e293b;border-radius:8px;overflow:hidden;}}
th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #334155;font-size:13px;}}
th{{background:#334155;color:#94a3b8;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px;}}
tr:hover{{background:#2d3a4e;}}
.status{{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:12px;}}
a{{color:#60a5fa;text-decoration:none;}}
a:hover{{text-decoration:underline;}}
.sub-status{{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:12px;margin:2px;}}
.bar{{display:flex;border-radius:8px;overflow:hidden;margin-bottom:24px;}}
.footer{{text-align:center;padding:30px;color:#64748b;font-size:13px;border-top:1px solid #334155;margin-top:40px;}}
</style>
</head>
<body>
<div class="header"><div class="container">
<h1>{domain} — 资产报告</h1>
<div class="meta">{now} &nbsp;|&nbsp; {status_dist}</div>
</div></div>
<div class="container">
<div class="stats">
<div class="stat-card"><div class="num">{len(resolved)}</div><div class="label">子域名</div></div>
<div class="stat-card"><div class="num">{len(all_ips)}</div><div class="label">唯一 IP</div></div>
<div class="stat-card"><div class="num">{total_open}</div><div class="label">开放端口</div></div>
<div class="stat-card green"><div class="num">{status_counts.get(200, 0)}</div><div class="label">HTTP 200</div></div>
<div class="stat-card yellow"><div class="num">{sum(status_counts.get(c, 0) for c in (301, 302, 307, 308))}</div><div class="label">重定向</div></div>
<div class="stat-card red"><div class="num">{errors}</div><div class="label">异常</div></div>
</div>
<div class="bar">{bar_html}</div>
<h2>子域名 ({len(resolved)})</h2>
<table><tr><th>子域名</th><th>IP</th></tr>{subs_html}</table>
<h2>HTTP 服务 ({len(http_results)})</h2>
<table><tr><th>状态</th><th>URL</th><th>标题</th><th>服务器</th><th>指纹</th><th>WAF</th></tr>{rows_html}</table>
<div class="footer">Generated by SRC-Recon &middot; {now}</div>
</div></body></html>"""

    suffix = "_quick_report.html" if quick else "_report.html"
    report_file = OUTPUT_DIR / f"{domain}{suffix}"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"HTML 报告已保存: {report_file}", "ok")
    return report_file


def main():
    parser = argparse.ArgumentParser(description="步骤6: 报告生成")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("--quick", action="store_true", help="快速模式报告")
    parser.add_argument("--resolved", help="解析结果文件")
    parser.add_argument("--asn", help="ASN 文件")
    parser.add_argument("--ports", help="端口扫描文件")
    parser.add_argument("--services", help="服务识别文件")
    parser.add_argument("--http", help="HTTP 探测文件")
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

    # 读取各步骤产出
    resolved = load_json(args.resolved or f"{domain}_resolved.json") or {}
    asn_info = load_json(args.asn or f"{domain}_asn.json") or []
    open_ports = load_json(args.ports or f"{domain}_ports.json") or {}
    services = load_json(args.services or f"{domain}_services.json") or []
    http_results = load_json(args.http or f"{domain}_http.json") or []

    all_ips = set()
    for v in resolved.values():
        if isinstance(v, dict):
            all_ips.update(v.get("ips", []))
        elif isinstance(v, list):
            all_ips.update(v)

    log(f"生成 {domain} 报告...")
    log("=" * 50)

    generate_txt_report(domain, resolved, sorted(all_ips), asn_info,
                        open_ports, services, http_results, args.quick)
    generate_html_report(domain, resolved, sorted(all_ips), asn_info,
                         open_ports, services, http_results, args.quick)


if __name__ == "__main__":
    main()
