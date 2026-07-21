#!/usr/bin/env python3
"""
资产收集工具 v2 - 全面版
功能：子域名收集 + IP/网段收集 + 端口扫描 + 服务识别 + FOFA/Shodan 查询
用法：python3 asset_recon.py <目标域名> [选项]
"""

import argparse
import asyncio
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from collections import defaultdict
from pathlib import Path

import dns.resolver
import requests

OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_DIR.mkdir(exist_ok=True)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# ── 配置 ──────────────────────────────────────────────────

class Config:
    # FOFA API（可选，有key则启用）
    FOFA_EMAIL = ""
    FOFA_KEY = ""
    # Shodan API（可选）
    SHODAN_KEY = ""
    # 扫描参数
    MAX_WORKERS = 50
    TIMEOUT = 10
    # 常见端口
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 162,
        389, 443, 445, 465, 512, 513, 514, 587, 636, 873, 993, 995,
        1080, 1433, 1521, 2049, 2181, 2375, 2376, 3000, 3306, 3389,
        4443, 5000, 5432, 5601, 5900, 5901, 6379, 7001, 7002, 8000,
        8001, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9443,
        10000, 11211, 27017, 28017, 50000, 50070, 61616,
    ]


def log(msg, level="info"):
    prefix = {"info": "ℹ️", "ok": "✅", "warn": "⚠️", "err": "❌"}.get(level, "ℹ️")
    print(f"[{time.strftime('%H:%M:%S')}] {prefix} {msg}", flush=True)


# ═════════════════════════════════════════════════════════
#  模块 1: 子域名收集
# ══════════════════════════════════════════════════════════

def crt_sh(domain):
    log(f"  查询 crt.sh 证书透明度日志...")
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=HEADERS, timeout=30)
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
        log(f"  crt.sh 失败: {e}", "warn")
    return set()


def hackertarget(domain):
    log(f"  查询 HackerTarget...")
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers=HEADERS, timeout=30)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            subs = set()
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if parts and "." in parts[0] and parts[0].endswith(f".{domain}"):
                    subs.add(parts[0].strip().lower())
            log(f"  HackerTarget → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  HackerTarget 失败: {e}", "warn")
    return set()


def rapiddns(domain):
    log(f"  查询 RapidDNS...")
    try:
        resp = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1", headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            subs = set(re.findall(r'>([\w\.\-]+\.' + re.escape(domain) + r')<', resp.text))
            log(f"  RapidDNS → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  RapidDNS 失败: {e}", "warn")
    return set()


def alienvault_otx(domain):
    log(f"  查询 AlienVault OTX...")
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", headers=HEADERS, timeout=30)
        if resp.status_code == 200:
            subs = set()
            for entry in resp.json().get("passive_dns", []):
                h = entry.get("hostname", "").lower()
                if h.endswith(f".{domain}") and "*" not in h:
                    subs.add(h)
            log(f"  AlienVault OTX → {len(subs)} 个子域名", "ok")
            return subs
    except Exception as e:
        log(f"  AlienVault OTX 失败: {e}", "warn")
    return set()


def dnsdumpster(domain):
    log(f"  查询 DNSDumpster...")
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        resp = session.get("https://dnsdumpster.com/", timeout=15)
        csrf = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', resp.text)
        if not csrf:
            return set()
        resp = session.post("https://dnsdumpster.com/", data={"csrfmiddlewaretoken": csrf.group(1), "targetip": domain}, timeout=30)
        subs = set(re.findall(r'>([\w\.\-]+\.' + re.escape(domain) + r')<', resp.text))
        log(f"  DNSDumpster → {len(subs)} 个子域名", "ok")
        return subs
    except Exception as e:
        log(f"  DNSDumpster 失败: {e}", "warn")
    return set()


def bufferover(domain):
    log(f"  查询 BufferOver.run...")
    try:
        resp = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", headers=HEADERS, timeout=30)
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
        log(f"  BufferOver 失败: {e}", "warn")
    return set()


def collect_subdomains(domain):
    """收集所有子域名"""
    log("🔍 开始子域名收集...", "info")
    all_subs = set()
    collectors = [crt_sh, hackertarget, rapiddns, alienvault_otx, bufferover, dnsdumpster]
    for func in collectors:
        subs = func(domain)
        all_subs.update(subs)
    log(f"被动收集完成，共 {len(all_subs)} 个唯一子域名", "ok")
    return all_subs


# ══════════════════════════════════════════════════════════
#  模块 2: DNS 解析 & IP 收集
# ══════════════════════════════════════════════════════════

def resolve_domain(domain, rtype="A"):
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def resolve_all(subdomains, max_workers=50):
    """批量 DNS 解析"""
    log(f"🔍 开始 DNS 解析 {len(subdomains)} 个子域名...")
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
    log(f"DNS 解析完成，{len(resolved)} 个有效", "ok")
    return resolved


def get_all_ips(resolved):
    """从解析结果中提取所有唯一 IP"""
    ips = set()
    for sub, ip_list in resolved.items():
        for ip in ip_list:
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except ValueError:
                pass
    return ips


# ══════════════════════════════════════════════════════════
#  模块 3: ASN / 网段收集
# ══════════════════════════════════════════════════════════

def get_asn_info(ip):
    """通过 IP 查询 ASN 信息"""
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
    """批量查询 ASN 信息"""
    log(f"🔍 开始查询 {len(ips)} 个 IP 的 ASN 信息...")
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
    log(f"ASN 查询完成，{len(results)} 个有结果", "ok")
    return results


# ══════════════════════════════════════════════════════════
#  模块 4: 端口扫描
# ══════════════════════════════════════════════════════════

def scan_port(ip, port, timeout=3):
    """扫描单个端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ips, ports=None, max_workers=100, timeout=3):
    """批量端口扫描"""
    if ports is None:
        ports = Config.COMMON_PORTS
    log(f"🔍 开始端口扫描 {len(ips)} 个 IP × {len(ports)} 个端口...")
    open_ports = defaultdict(list)
    total = len(ips) * len(ports)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for ip in ips:
            for port in ports:
                futures[pool.submit(scan_port, ip, port, timeout)] = (ip, port)

        for future in concurrent.futures.as_completed(futures):
            ip, port = futures[future]
            done += 1
            try:
                result = future.result()
                if result:
                    open_ports[ip].append(result)
            except Exception:
                pass

            if done % 500 == 0:
                log(f"  进度: {done}/{total} ({done*100//total}%)")

    log(f"端口扫描完成，{sum(len(v) for v in open_ports.values())} 个开放端口", "ok")
    return dict(open_ports)


# ══════════════════════════════════════════════════════════
#  模块 5: 服务识别
# ══════════════════════════════════════════════════════════

def identify_service(ip, port, timeout=5):
    """识别端口服务"""
    service_info = {"ip": ip, "port": port, "service": "", "banner": "", "ssl": False}

    # 尝试 SSL 连接
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=ip)
        ssock.connect((ip, port))
        ssock.send(b"GET / HTTP/1.0\r\n\r\n")
        banner = ssock.recv(4096).decode("utf-8", errors="ignore")
        ssock.close()
        service_info["ssl"] = True
        service_info["banner"] = banner[:200]
        # 从 banner 提取服务信息
        if "Server:" in banner:
            m = re.search(r'Server:\s*(.+?)[\r\n]', banner)
            if m:
                service_info["service"] = m.group(1).strip()
        return service_info
    except Exception:
        pass

    # 普通 TCP 连接
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # 发送探测数据
        if port == 21:
            sock.send(b"")
        elif port == 22:
            sock.send(b"")
        elif port == 25:
            sock.send(b"EHLO test\r\n")
        elif port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 443 or port == 8443:
            sock.send(b"")
        elif port == 3306:
            sock.send(b"")
        elif port == 6379:
            sock.send(b"INFO\r\n")
        else:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")

        banner = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()
        service_info["banner"] = banner[:200]

        # 服务识别
        if port == 21:
            service_info["service"] = "FTP"
        elif port == 22:
            service_info["service"] = "SSH"
        elif port == 23:
            service_info["service"] = "Telnet"
        elif port == 25:
            service_info["service"] = "SMTP"
        elif port == 53:
            service_info["service"] = "DNS"
        elif port == 80 or port == 8080 or port == 8000 or port == 8888:
            service_info["service"] = "HTTP"
        elif port == 443 or port == 8443:
            service_info["service"] = "HTTPS"
        elif port == 3306:
            service_info["service"] = "MySQL"
        elif port == 5432:
            service_info["service"] = "PostgreSQL"
        elif port == 6379:
            service_info["service"] = "Redis"
        elif port == 27017:
            service_info["service"] = "MongoDB"
        elif port == 11211:
            service_info["service"] = "Memcached"
        elif port == 9200:
            service_info["service"] = "Elasticsearch"
        elif port == 5601:
            service_info["service"] = "Kibana"
        elif port == 3389:
            service_info["service"] = "RDP"
        elif port == 5900:
            service_info["service"] = "VNC"
        else:
            service_info["service"] = "Unknown"

        # 从 banner 提取版本
        if "Server:" in banner:
            m = re.search(r'Server:\s*(.+?)[\r\n]', banner)
            if m:
                service_info["service"] = m.group(1).strip()

        return service_info
    except Exception:
        service_info["service"] = "Unknown"
        return service_info


def identify_services(open_ports, max_workers=50):
    """批量服务识别"""
    log(f"🔍 开始服务识别...")
    results = []
    tasks = []
    for ip, ports in open_ports.items():
        for port in ports:
            tasks.append((ip, port))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(identify_service, ip, port): (ip, port) for ip, port in tasks}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception:
                pass

    log(f"服务识别完成，{len(results)} 个服务", "ok")
    return results


# ══════════════════════════════════════════════════════════
#  模块 6: HTTP 探测
# ══════════════════════════════════════════════════════════

def http_probe(subdomains, max_workers=50):
    """HTTP 探测"""
    log(f" 开始 HTTP 探测 {len(subdomains)} 个子域名...")
    results = []

    def probe(sub):
        for scheme in ["https", "http"]:
            url = f"{scheme}://{sub}"
            try:
                resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True, verify=False)
                title = re.sub(r'<[^>]+>', '', resp.text[:500]).strip()[:100]
                return {"subdomain": sub, "url": resp.url, "status": resp.status_code, "title": title, "server": resp.headers.get("Server", "")}
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

    log(f"HTTP 探测完成，{len(results)} 个可访问", "ok")
    return results


# ══════════════════════════════════════════════════════════
#  模块 7: FOFA 查询（可选）
# ══════════════════════════════════════════════════════════

def fofa_query(domain, email=None, key=None, size=100):
    """FOFA 资产查询"""
    if not email or not key:
        log("FOFA API 未配置，跳过", "warn")
        return []

    log(f"🔍 查询 FOFA: domain=\"{domain}\"...")
    try:
        query = f'domain="{domain}"'
        import base64
        qbase64 = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={qbase64}&size={size}&fields=host,ip,port,protocol,server,product"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("error", False):
                log(f"FOFA 错误: {data.get('errmsg', '')}", "err")
                return []
            results = data.get("results", [])
            log(f"FOFA → {len(results)} 条结果", "ok")
            return results
    except Exception as e:
        log(f"FOFA 查询失败: {e}", "warn")
    return []


# ══════════════════════════════════════════════════════════
#  报告生成
# ══════════════════════════════════════════════════════════

def generate_report(domain, resolved, all_ips, asn_info, open_ports, services, http_results, fofa_results):
    """生成综合报告"""
    report_file = OUTPUT_DIR / f"{domain}_full_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"{'='*70}\n")
        f.write(f"  {domain} 全面资产收集报告\n")
        f.write(f"{'='*70}\n")
        f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # 摘要
        f.write(f"📊 摘要:\n")
        f.write(f"  子域名总数: {len(resolved)}\n")
        f.write(f"  唯一 IP 数: {len(all_ips)}\n")
        f.write(f"  开放端口数: {sum(len(v) for v in open_ports.values())}\n")
        f.write(f"  HTTP 可访问: {len(http_results)}\n")
        f.write(f"  FOFA 结果: {len(fofa_results)}\n\n")

        # ASN 分布
        if asn_info:
            f.write(f" ASN / 组织分布:\n")
            orgs = defaultdict(list)
            for info in asn_info:
                org = info.get("org", "Unknown")
                orgs[org].append(info["ip"])
            for org, ips in sorted(orgs.items(), key=lambda x: -len(x[1])):
                f.write(f"  {org}: {len(ips)} 个 IP\n")
                for ip in sorted(ips)[:5]:
                    f.write(f"    - {ip}\n")
                if len(ips) > 5:
                    f.write(f"    ... 还有 {len(ips)-5} 个\n")
            f.write("\n")

        # 子域名列表
        f.write(f"🔗 子域名列表 ({len(resolved)} 个):\n")
        for sub in sorted(resolved.keys()):
            ips = ", ".join(resolved[sub])
            f.write(f"  {sub} → {ips}\n")
        f.write("\n")

        # 开放端口
        f.write(f"🔓 开放端口:\n")
        for ip in sorted(open_ports.keys()):
            ports = ", ".join(str(p) for p in sorted(open_ports[ip]))
            f.write(f"  {ip}: {ports}\n")
        f.write("\n")

        # 服务识别
        f.write(f"⚙️  服务识别:\n")
        for svc in sorted(services, key=lambda x: (x["ip"], x["port"])):
            ssl_tag = " [SSL]" if svc["ssl"] else ""
            f.write(f"  {svc['ip']}:{svc['port']} → {svc['service']}{ssl_tag}\n")
            if svc["banner"]:
                banner = svc["banner"][:100].replace("\n", " ").replace("\r", "")
                f.write(f"    Banner: {banner}\n")
        f.write("\n")

        # HTTP 结果
        f.write(f"🌐 HTTP 服务:\n")
        status_counts = defaultdict(int)
        for r in http_results:
            status_counts[r["status"]] += 1
        f.write(f"  状态码分布: ")
        f.write(", ".join(f"{code}: {count}个" for code, count in sorted(status_counts.items())))
        f.write("\n\n")

        for r in sorted(http_results, key=lambda x: x["status"]):
            f.write(f"  [{r['status']}] {r['url']}\n")
            if r["title"]:
                f.write(f"    标题: {r['title'][:80]}\n")
            if r["server"]:
                f.write(f"    服务器: {r['server']}\n")
        f.write("\n")

        # FOFA 结果
        if fofa_results:
            f.write(f"🔎 FOFA 结果:\n")
            for item in fofa_results[:50]:
                f.write(f"  {item}\n")

    log(f"报告已保存: {report_file}", "ok")
    return report_file


# ══════════════════════════════════════════════════════════
#  主流程
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="资产收集工具 v2 - 全面版")
    parser.add_argument("domain", help="目标域名，如 lenovo.com")
    parser.add_argument("--skip-portscan", action="store_true", help="跳过端口扫描")
    parser.add_argument("--skip-service", action="store_true", help="跳过服务识别")
    parser.add_argument("--ports", type=str, help="自定义端口列表，逗号分隔")
    parser.add_argument("--fofa-email", default="", help="FOFA 邮箱")
    parser.add_argument("--fofa-key", default="", help="FOFA API Key")
    parser.add_argument("--shodan-key", default="", help="Shodan API Key")
    parser.add_argument("--workers", type=int, default=50, help="并发数")
    args = parser.parse_args()

    domain = args.domain
    Config.FOFA_EMAIL = args.fofa_email
    Config.FOFA_KEY = args.fofa_key
    Config.SHODAN_KEY = args.shodan_key
    Config.MAX_WORKERS = args.workers

    log(f"{'='*60}", "info")
    log(f"开始收集 {domain} 资产", "info")
    log(f"{'='*60}", "info")
    start = time.time()

    # 1. 子域名收集
    all_subs = collect_subdomains(domain)

    # 2. DNS 解析
    resolved = resolve_all(all_subs, Config.MAX_WORKERS)
    all_ips = get_all_ips(resolved)
    log(f"收集到 {len(all_ips)} 个唯一 IP", "ok")

    # 保存子域名结果
    subs_file = OUTPUT_DIR / f"{domain}_subdomains.json"
    with open(subs_file, "w") as f:
        json.dump({s: {"ips": ips} for s, ips in sorted(resolved.items())}, f, indent=2, ensure_ascii=False)

    # 3. ASN 查询
    asn_info = collect_asn_info(all_ips, 10)
    asn_file = OUTPUT_DIR / f"{domain}_asn.json"
    with open(asn_file, "w") as f:
        json.dump(asn_info, f, indent=2, ensure_ascii=False)

    # 4. 端口扫描
    open_ports = {}
    if not args.skip_portscan and all_ips:
        ports = Config.COMMON_PORTS
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        open_ports = scan_ports(all_ips, ports, 100, 3)
        ports_file = OUTPUT_DIR / f"{domain}_ports.json"
        with open(ports_file, "w") as f:
            json.dump(open_ports, f, indent=2)

    # 5. 服务识别
    services = []
    if not args.skip_service and open_ports:
        services = identify_services(open_ports, 50)
        svc_file = OUTPUT_DIR / f"{domain}_services.json"
        with open(svc_file, "w") as f:
            json.dump(services, f, indent=2, ensure_ascii=False)

    # 6. HTTP 探测
    http_results = http_probe(list(resolved.keys()), Config.MAX_WORKERS)
    http_file = OUTPUT_DIR / f"{domain}_http.json"
    with open(http_file, "w") as f:
        json.dump(http_results, f, indent=2, ensure_ascii=False)

    # 7. FOFA 查询
    fofa_results = fofa_query(domain, Config.FOFA_EMAIL, Config.FOFA_KEY)

    # 8. 生成报告
    report_file = generate_report(domain, resolved, all_ips, asn_info, open_ports, services, http_results, fofa_results)

    elapsed = time.time() - start
    log(f"{'='*60}", "info")
    log(f"收集完成！耗时 {elapsed:.1f} 秒", "ok")
    log(f"结果目录: {OUTPUT_DIR}", "info")
    log(f"报告文件: {report_file}", "info")


if __name__ == "__main__":
    main()
