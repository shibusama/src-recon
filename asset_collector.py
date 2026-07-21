#!/usr/bin/env python3
"""
资产收集脚本 - 用于 SRC 漏洞挖掘前期信息收集
功能：子域名收集 / DNS解析 / 端口扫描 / HTTP探测 / 指纹识别
用法：python3 asset_collector.py -d example.com
"""

import argparse
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import dns.resolver
import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

# ─── 配置 ───────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "vpn", "portal", "admin", "api", "app", "dev",
    "test", "staging", "uat", "prod", "blog", "shop", "store", "m", "mobile",
    "img", "image", "static", "cdn", "media", "file", "files", "download",
    "upload", "db", "database", "mysql", "redis", "elasticsearch", "kibana",
    "grafana", "jenkins", "git", "gitlab", "svn", "wiki", "docs", "help",
    "support", "service", "services", "login", "sso", "auth", "oauth",
    "sso", "cas", "ldap", "oa", "erp", "crm", "hr", "finance", "pay",
    "payment", "order", "trade", "exchange", "gateway", "proxy", "waf",
    "monitor", "nagios", "zabbix", "prometheus", "log", "syslog", "ntp",
    "backup", "bak", "data", "report", "bi", "analytics", "search",
    "internal", "intranet", "extranet", "manage", "management", "console",
    "dashboard", "panel", "pma", "phpmyadmin", "adminer", "tomcat", "weblogic",
    "jboss", "was", "iis", "exchange", "owa", "activesync", "autodiscover",
    "sip", "lync", "meet", "video", "live", "stream", "radio", "podcast",
    "chat", "im", "push", "notify", "notification", "email", "sms",
    "wechat", "weixin", "mini", "miniprogram", "h5", "webapp", "wx",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 512, 513, 514, 515, 587, 631, 636, 873, 902, 990, 993, 995, 1025,
    1080, 1433, 1434, 1521, 1723, 2049, 2080, 2082, 2083, 2086, 2087, 2095,
    2096, 2181, 3000, 3128, 3306, 3389, 4000, 4443, 5000, 5001, 5432, 5601,
    5672, 5900, 5901, 6379, 6443, 7001, 7002, 7077, 8000, 8001, 8008, 8009,
    8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8091, 8092, 8093, 8095, 8161, 8443, 8448, 8500, 8880, 8888, 8983, 9000,
    9001, 9080, 9081, 9090, 9091, 9200, 9300, 9443, 10000, 10250, 11211,
    15672, 27017, 27018, 50000, 50070, 61616,
]

TIMEOUT = 5
MAX_THREADS = 50
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ─── 子域名收集 ──────────────────────────────────────────
def collect_from_crtsh(domain):
    """通过 crt.sh (证书透明度) 收集子域名"""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": USER_AGENT}, verify=False)
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        subdomains.add(line)
    except Exception as e:
        print(f"  [!] crt.sh 请求失败: {e}")
    return subdomains


def collect_from_hackertarget(domain):
    """通过 HackerTarget API 收集子域名"""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 1:
                    host = parts[0].strip().lower()
                    if host.endswith(domain):
                        subdomains.add(host)
    except Exception as e:
        print(f"  [!] HackerTarget 请求失败: {e}")
    return subdomains


def collect_from_alienvault(domain):
    """通过 AlienVault OTX 收集子域名"""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": USER_AGENT}, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("url_list", []):
                parsed = entry.get("url", "")
                match = re.search(r"https?://([^/:]+)", parsed)
                if match:
                    host = match.group(1).lower()
                    if host.endswith(domain):
                        subdomains.add(host)
    except Exception as e:
        print(f"  [!] AlienVault 请求失败: {e}")
    return subdomains


def brute_subdomains(domain, wordlist=None):
    """字典爆破子域名"""
    subs = set()
    words = wordlist or COMMON_SUBDOMAINS
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "114.114.114.114"]
    resolver.lifetime = 3

    def check(sub):
        full = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full, "A")
            ips = [r.address for r in answers]
            return full, ips
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
        futures = {pool.submit(check, s): s for s in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subs.add(result[0])
    return subs


def collect_subdomains(domain):
    """汇总所有子域名收集结果"""
    all_subs = set()

    print(f"\n{'='*60}")
    print(f"  [1/4] 子域名收集 - {domain}")
    print(f"{'='*60}")

    print("  [*] crt.sh (证书透明度)...")
    subs = collect_from_crtsh(domain)
    print(f"      找到 {len(subs)} 个")
    all_subs.update(subs)

    print("  [*] HackerTarget...")
    subs = collect_from_hackertarget(domain)
    print(f"      找到 {len(subs)} 个")
    all_subs.update(subs)

    print("  [*] AlienVault OTX...")
    subs = collect_from_alienvault(domain)
    print(f"      找到 {len(subs)} 个")
    all_subs.update(subs)

    print("  [*] 字典爆破 (常见子域名)...")
    subs = brute_subdomains(domain)
    print(f"      找到 {len(subs)} 个")
    all_subs.update(subs)

    print(f"\n  [+] 子域名合计: {len(all_subs)} 个")
    return sorted(all_subs)


# ─── DNS 解析 ─────────────────────────────────────────────
def resolve_dns(subdomains):
    """解析子域名的 A 记录和 CNAME"""
    print(f"\n{'='*60}")
    print(f"  [2/4] DNS 解析")
    print(f"{'='*60}")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "114.114.114.114"]
    resolver.lifetime = 3
    results = {}

    for sub in subdomains:
        records = {"A": [], "CNAME": [], "MX": [], "TXT": []}
        for rtype in ["A", "CNAME"]:
            try:
                answers = resolver.resolve(sub, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        results[sub] = records
        ip_str = ", ".join(records["A"]) if records["A"] else "N/A"
        print(f"  {sub:<40} -> {ip_str}")

    return results


# ─── 端口扫描 ─────────────────────────────────────────────
def scan_port(host, port):
    """扫描单个端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_ports(targets, ports=None):
    """扫描目标 IP 的开放端口"""
    ports = ports or COMMON_PORTS
    print(f"\n{'='*60}")
    print(f"  [3/4] 端口扫描 (共 {len(ports)} 个端口)")
    print(f"{'='*60}")

    open_ports = {}
    for host, info in targets.items():
        ips = info.get("A", [])
        if not ips:
            continue
        ip = ips[0]
        print(f"\n  [*] 扫描 {host} ({ip})...")
        host_ports = []

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
            futures = {pool.submit(scan_port, ip, p): p for p in ports}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    host_ports.append(port)

        host_ports.sort()
        open_ports[host] = host_ports
        if host_ports:
            print(f"      开放端口: {', '.join(map(str, host_ports))}")
        else:
            print(f"      无开放端口")

    return open_ports


# ─── HTTP 探测 ────────────────────────────────────────────
def probe_http(host, port):
    """HTTP 服务探测与指纹识别"""
    scheme = "https" if port in [443, 8443, 9443, 4443] else "http"
    url = f"{scheme}://{host}:{port}"
    result = {"url": url, "status": None, "title": None, "server": None, "tech": []}

    try:
        resp = requests.get(
            url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
            verify=False, allow_redirects=True
        )
        result["status"] = resp.status_code
        result["server"] = resp.headers.get("Server", "")
        result["final_url"] = resp.url

        # 提取 title
        soup = BeautifulSoup(resp.text[:50000], "html.parser")
        title_tag = soup.find("title")
        if title_tag:
            result["title"] = title_tag.get_text(strip=True)

        # 简单指纹识别
        body = resp.text[:100000].lower()
        tech_map = {
            "wordpress": "WordPress",
            "wp-content": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "thinkphp": "ThinkPHP",
            "laravel": "Laravel",
            "spring": "Spring Framework",
            "django": "Django",
            "flask": "Flask",
            "express": "Express.js",
            "vue": "Vue.js",
            "react": "React",
            "angular": "Angular",
            "bootstrap": "Bootstrap",
            "jquery": "jQuery",
            "phpmyadmin": "phpMyAdmin",
            "jenkins": "Jenkins",
            "grafana": "Grafana",
            "kibana": "Kibana",
            "tomcat": "Apache Tomcat",
            "weblogic": "WebLogic",
            "jboss": "JBoss",
            "nginx": "Nginx",
            "apache": "Apache",
            "iis": "IIS",
            "swagger": "Swagger UI",
            "elasticsearch": "Elasticsearch",
        }
        for keyword, tech in tech_map.items():
            if keyword in body:
                result["tech"].append(tech)
        result["tech"] = list(set(result["tech"]))

    except requests.exceptions.SSLError:
        # 尝试另一个 scheme
        alt_scheme = "http" if scheme == "https" else "https"
        alt_url = f"{alt_scheme}://{host}:{port}"
        try:
            resp = requests.get(
                alt_url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                verify=False, allow_redirects=True
            )
            result["url"] = alt_url
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("Server", "")
            result["final_url"] = resp.url
            soup = BeautifulSoup(resp.text[:50000], "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                result["title"] = title_tag.get_text(strip=True)
        except Exception:
            pass
    except Exception:
        pass

    return result


def http_probe(targets, open_ports):
    """对所有开放 HTTP 端口的目标进行探测"""
    print(f"\n{'='*60}")
    print(f"  [4/4] HTTP 探测与指纹识别")
    print(f"{'='*60}")

    http_ports = {
        80, 81, 443, 8080, 8081, 8443, 8888, 9090, 9443,
        3000, 4000, 5000, 7001, 8000, 8008, 8082, 8083,
        8085, 8086, 8088, 8090, 9000, 9080, 4443,
    }
    http_results = {}

    for host, ports in open_ports.items():
        http_port_list = [p for p in ports if p in http_ports]
        if not http_port_list:
            continue

        for port in http_port_list:
            print(f"  [*] 探测 {host}:{port}...")
            result = probe_http(host, port)
            key = f"{host}:{port}"
            http_results[key] = result

            status = result.get("status") or "-"
            title = result.get("title") or "-"
            server = result.get("server") or "-"
            tech = ", ".join(result.get("tech", [])) or "-"
            print(f"      状态: {status} | 标题: {title}")
            print(f"      Server: {server}")
            if result.get("tech"):
                print(f"      指纹: {tech}")

    return http_results


# ─── 报告输出 ─────────────────────────────────────────────
def generate_report(domain, subdomains, dns_info, port_info, http_info):
    """生成 JSON 报告"""
    report = {
        "target": domain,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "dns": dns_info,
        "open_ports": port_info,
        "http_services": http_info,
    }

    filename = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*60}")
    print(f"  [+] 报告已保存: {filename}")
    print(f"{'='*60}")
    return filename


# ─── 汇总 ─────────────────────────────────────────────────
def print_summary(subdomains, dns_info, port_info, http_info):
    """打印汇总"""
    print(f"\n{'='*60}")
    print(f"  扫描汇总")
    print(f"{'='*60}")
    print(f"  子域名数量:   {len(subdomains)}")

    alive = sum(1 for v in dns_info.values() if v.get("A"))
    print(f"  存活主机:     {alive}")

    total_ports = sum(len(v) for v in port_info.values())
    print(f"  开放端口总数: {total_ports}")
    print(f"  HTTP 服务数:  {len(http_info)}")

    # 列出有趣的发现
    interesting = []
    for key, info in http_info.items():
        techs = info.get("tech", [])
        if any(t in techs for t in ["phpMyAdmin", "Jenkins", "Grafana", "Kibana", "Swagger UI"]):
            interesting.append(f"  ⚠ {key} -> {', '.join(techs)}")
    if interesting:
        print(f"\n  ⚠ 值得关注的服务:")
        for item in interesting:
            print(f"    {item}")


# ─── 主函数 ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SRC 资产收集工具")
    parser.add_argument("-d", "--domain", required=True, help="目标域名 (如 example.com)")
    parser.add_argument("-p", "--ports", nargs="*", type=int, help="自定义端口列表 (默认扫描常见端口)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="并发线程数 (默认 50)")
    parser.add_argument("--skip-port-scan", action="store_true", help="跳过端口扫描")
    parser.add_argument("--skip-http", action="store_true", help="跳过 HTTP 探测")
    parser.add_argument("-w", "--wordlist", help="自定义子域名字典文件")
    args = parser.parse_args()

    global MAX_THREADS
    MAX_THREADS = args.threads

    domain = args.domain.strip()
    if domain.startswith("http"):
        domain = re.sub(r"https?://", "", domain).rstrip("/")

    banner = f"""
╔══════════════════════════════════════════════════════════╗
║              SRC 资产收集工具 v1.0                       ║
║              目标: {domain:<40} ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)
    start_time = time.time()

    # 1. 子域名收集
    subdomains = collect_subdomains(domain)

    # 2. DNS 解析
    dns_info = resolve_dns(subdomains)

    # 3. 端口扫描
    if not args.skip_port_scan:
        ports = args.ports if args.ports else COMMON_PORTS
        port_info = scan_ports(dns_info, ports)
    else:
        port_info = {}
        print(f"\n  [*] 跳过端口扫描")

    # 4. HTTP 探测
    if not args.skip_http and port_info:
        http_info = http_probe(dns_info, port_info)
    else:
        http_info = {}
        if args.skip_http:
            print(f"\n  [*] 跳过 HTTP 探测")

    # 输出报告
    generate_report(domain, subdomains, dns_info, port_info, http_info)
    print_summary(subdomains, dns_info, port_info, http_info)

    elapsed = time.time() - start_time
    print(f"\n  [*] 总耗时: {elapsed:.1f} 秒\n")


if __name__ == "__main__":
    main()
