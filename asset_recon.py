#!/usr/bin/env python3
"""
资产收集工具 v3 - 综合版
合并自 asset_recon.py（全面版）+ asset_collector.py（增强版）+ recon.py（轻量版）

功能：子域名收集（6 被动源 + DNS 爆破）/ DNS 解析 / ASN 查询 / 端口扫描
      / 服务识别 / HTTP 探测 / 指纹识别 / FOFA 查询
用法：python3 asset_recon.py <目标域名> [选项]
"""

import argparse
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

requests.packages.urllib3.disable_warnings()

# ── 路径与输出 ──────────────────────────────────────────────
OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_DIR.mkdir(exist_ok=True)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ── 配置 ─────────────────────────────────────────────────────
class Config:
    FOFA_EMAIL = ""
    FOFA_KEY = ""
    SHODAN_KEY = ""
    MAX_WORKERS = 50
    TIMEOUT = 5


# ── 常见端口（合并 asset_collector + asset_recon）─────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 389,
    443, 445, 465, 512, 513, 514, 515, 587, 631, 636, 873, 902, 990, 993,
    995, 1025, 1080, 1433, 1434, 1521, 1723, 2049, 2080, 2082, 2083, 2086,
    2087, 2095, 2096, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 4000, 4443,
    5000, 5001, 5432, 5601, 5672, 5900, 5901, 6379, 6443, 7001, 7002, 7077,
    8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
    8087, 8088, 8089, 8090, 8091, 8092, 8093, 8095, 8161, 8443, 8448, 8500,
    8880, 8888, 8983, 9000, 9001, 9080, 9081, 9090, 9091, 9200, 9300, 9443,
    10000, 10250, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 61616,
]

# ── 常见子域名（合并 asset_collector + recon）────────────────
COMMON_SUBS = [
    # 基础
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "imap",
    "ns1", "ns2", "dns", "dns1", "dns2",
    # 管理入口
    "admin", "portal", "login", "sso", "auth", "oauth", "cas", "ldap",
    "console", "dashboard", "panel", "manage", "management",
    "pma", "phpmyadmin", "adminer",
    # 应用服务
    "api", "app", "web", "mobile", "m", "h5", "webapp", "wx", "mini",
    "dev", "test", "staging", "uat", "prod", "beta", "demo",
    # 开发与 CI/CD
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "build",
    "jira", "confluence", "wiki", "docs",
    # 运维监控
    "monitor", "nagios", "zabbix", "prometheus", "grafana", "kibana",
    "elasticsearch", "log", "syslog", "ntp", "backup", "bak",
    # 云与基础设施
    "cloud", "aws", "azure", "gcp", "server", "proxy", "gateway",
    "lb", "loadbalancer", "cache", "cdn", "static", "assets",
    "img", "image", "images", "media", "file", "files", "download", "upload",
    # 通讯
    "vpn", "remote", "office", "internal", "intranet", "extranet", "corp",
    "sip", "meet", "video", "live", "stream", "chat", "im",
    "email", "mail2", "exchange", "owa", "activesync", "autodiscover",
    # 业务系统
    "oa", "erp", "crm", "hr", "finance", "pay", "payment",
    "order", "trade", "exchange", "shop", "store", "cart", "checkout",
    "blog", "news", "support", "help", "kb", "forum", "community",
    # 安全
    "security", "sec", "soc", "cert", "waf",
    # 数据与 AI
    "data", "database", "db", "mysql", "redis", "bi", "analytics",
    "ai", "ml", "iot", "smart",
    # 地区
    "us", "cn", "eu", "asia", "ap", "jp", "kr", "tw", "hk", "sg",
    "us2", "eu2", "ap2",
    # 合作与招聘
    "partner", "affiliate", "reseller", "dealer",
    "training", "learn", "edu", "academy", "event", "events",
    "careers", "job", "jobs", "recruit",
    # 其他
    "service", "services", "notification", "notify", "push",
    "report", "search", "status", "health",
]

# ── 指纹库（CMS / 框架 / 中间件，来自 asset_collector）──────
TECH_MAP = {
    # CMS
    "wordpress": "WordPress", "wp-content": "WordPress",
    "wp-json": "WordPress", "wp-includes": "WordPress",
    "drupal": "Drupal", "joomla": "Joomla",
    # PHP 框架
    "thinkphp": "ThinkPHP", "laravel": "Laravel",
    # Java 框架
    "spring": "Spring Framework", "springboot": "Spring Boot",
    "struts": "Apache Struts",
    # Python 框架
    "django": "Django", "flask": "Flask", "csrftoken": "Django",
    # JS 框架
    "express": "Express.js",
    "next.js": "Next.js", "nuxt": "Nuxt.js",
    # 前端框架
    "vue": "Vue.js", "react": "React", "angular": "Angular",
    # UI 框架
    "bootstrap": "Bootstrap", "jquery": "jQuery",
    # 中间件
    "tomcat": "Apache Tomcat", "weblogic": "WebLogic",
    "jboss": "JBoss", "wildfly": "WildFly",
    "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
    "caddy": "Caddy", "traefik": "Traefik",
    # 管理工具
    "phpmyadmin": "phpMyAdmin", "adminer": "Adminer",
    "jenkins": "Jenkins", "hudson": "Hudson",
    "grafana": "Grafana", "kibana": "Kibana",
    "prometheus": "Prometheus", "alertmanager": "Alertmanager",
    # API 与文档
    "swagger": "Swagger UI", "api-docs": "Swagger UI",
    "redoc": "ReDoc", "graphql": "GraphQL",
    # 数据库管理
    "elasticsearch": "Elasticsearch", "cerebro": "Cerebro",
    "redis": "Redis", "redis-commander": "Redis Commander",
    # 其他
    "sentry": "Sentry", "gitlab": "GitLab",
    "rocket.chat": "Rocket.Chat", "mattermost": "Mattermost",
    "php": "PHP",
}

WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai": "Akamai",
    "akamai-": "Akamai",
    "x-cdn": "CDNetworks",
    "x-powered-by-360wzb": "360WAF",
    "x-waf": "Web Application Firewall",
    "server: yunjiasu-nginx": "Baidu Yunjiasu",
}


# ══════════════════════════════════════════════════════════════
#  工具函数
# ══════════════════════════════════════════════════════════════

def log(msg, level="info"):
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}.get(level, "[*]")
    print(f"[{time.strftime('%H:%M:%S')}] {prefix} {msg}", flush=True)


# ══════════════════════════════════════════════════════════════
#  模块 1：子域名收集（被动）
# ══════════════════════════════════════════════════════════════

def crt_sh(domain):
    """从 crt.sh 证书透明度日志获取子域名"""
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
    """从 HackerTarget API 获取子域名"""
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
    """从 RapidDNS 获取子域名"""
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
    """从 AlienVault OTX 获取子域名"""
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
    """从 DNSDumpster 获取子域名"""
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
    """从 BufferOver.run 获取子域名"""
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
    """运行所有被动收集源，去重合并"""
    all_subs = set()
    collectors = [crt_sh, hackertarget, rapiddns, alienvault_otx, dnsdumpster, bufferover]
    for func in collectors:
        subs = func(domain)
        all_subs.update(subs)
    log(f"被动收集完成，共 {len(all_subs)} 个唯一子域名", "ok")
    return all_subs


# ══════════════════════════════════════════════════════════════
#  模块 2：DNS 爆破
# ══════════════════════════════════════════════════════════════

def dns_resolve(subdomain):
    """尝试解析单个子域名的 A 记录"""
    try:
        answers = dns.resolver.resolve(subdomain, "A")
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None


def brute_force_subdomains(domain, wordlist=None):
    """DNS 爆破子域名"""
    words = wordlist or COMMON_SUBS
    log(f"  开始 DNS 爆破，测试 {len(words)} 个常见子域名...")
    found = {}

    def check(sub):
        full = f"{sub}.{domain}"
        ips = dns_resolve(full)
        return (full, ips) if ips else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(check, s): s for s in words}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found[result[0]] = result[1]

    log(f"  DNS 爆破发现 {len(found)} 个有效子域名", "ok")
    return found


# ══════════════════════════════════════════════════════════════
#  模块 3：DNS 解析
# ══════════════════════════════════════════════════════════════

def resolve_domain(domain, rtype="A"):
    """解析单个域名的指定记录类型"""
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def resolve_all(subdomains, max_workers=None):
    """批量 DNS 解析"""
    mw = max_workers or Config.MAX_WORKERS
    log(f"  开始 DNS 解析验证 {len(subdomains)} 个子域名...")
    resolved = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=mw) as pool:
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


# ══════════════════════════════════════════════════════════════
#  模块 4：ASN / 组织查询
# ══════════════════════════════════════════════════════════════

def get_asn_info(ip):
    """通过 ipinfo.io 查询 ASN 信息"""
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


# ══════════════════════════════════════════════════════════════
#  模块 5：端口扫描
# ══════════════════════════════════════════════════════════════

def scan_port(ip, port, timeout=None):
    """扫描单个端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout or Config.TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ips, ports=None, max_workers=100):
    """批量端口扫描"""
    ports = ports or COMMON_PORTS
    log(f"  开始端口扫描 {len(ips)} 个 IP × {len(ports)} 个端口...")
    open_ports = defaultdict(list)
    total = len(ips) * len(ports)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for ip in ips:
            for port in ports:
                futures[pool.submit(scan_port, ip, port)] = (ip, port)

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
                log(f"    进度: {done}/{total} ({done * 100 // total}%)")

    log(f"  端口扫描完成，{sum(len(v) for v in open_ports.values())} 个开放端口", "ok")
    return dict(open_ports)


# ══════════════════════════════════════════════════════════════
#  模块 6：服务识别
# ══════════════════════════════════════════════════════════════

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 631: "IPP",
    636: "LDAPS", 873: "Rsync", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker TLS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ",
    5900: "VNC", 5901: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 15672: "RabbitMQ-Manage", 27017: "MongoDB",
    50000: "DB2", 61616: "ActiveMQ",
}


def identify_service(ip, port, timeout=None):
    """识别端口的服务与 banner"""
    info = {"ip": ip, "port": port, "service": SERVICE_PORTS.get(port, "Unknown"), "banner": "", "ssl": False}
    t = timeout or Config.TIMEOUT

    # 先尝试 SSL 连接
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(t)
        ssock = ctx.wrap_socket(sock, server_hostname=ip)
        ssock.connect((ip, port))
        ssock.send(b"GET / HTTP/1.0\r\n\r\n")
        banner = ssock.recv(4096).decode("utf-8", errors="ignore")
        ssock.close()
        info["ssl"] = True
        info["banner"] = banner[:300]
        m = re.search(r"Server:\s*(.+?)[\r\n]", banner)
        if m:
            info["service"] = m.group(1).strip()
        return info
    except Exception:
        pass

    # 普通 TCP 连接
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(t)
        sock.connect((ip, port))

        # 按端口发送探测 payload
        payloads = {
            21: b"",
            22: b"",
            25: b"EHLO test\r\n",
            3306: b"",
            6379: b"INFO\r\n",
        }
        payload = payloads.get(port, b"GET / HTTP/1.0\r\n\r\n")
        sock.send(payload)

        banner = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()
        info["banner"] = banner[:300]

        # 从 banner 提取 Server 头
        m = re.search(r"Server:\s*(.+?)[\r\n]", banner)
        if m:
            info["service"] = m.group(1).strip()

        return info
    except Exception:
        return info


def identify_services(open_ports, max_workers=50):
    """批量服务识别"""
    log("  开始服务识别...")
    results = []
    tasks = [(ip, port) for ip, ports in open_ports.items() for port in ports]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(identify_service, ip, port): (ip, port) for ip, port in tasks}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    log(f"  服务识别完成，{len(results)} 个服务", "ok")
    return results


# ══════════════════════════════════════════════════════════════
#  模块 7：HTTP 探测 & 指纹识别
# ══════════════════════════════════════════════════════════════

def detect_waf(headers):
    """检测 WAF（从响应头识别）"""
    detected = []
    for key_lower, waf_name in WAF_HEADERS.items():
        for header_key in headers:
            if header_key.lower() == key_lower or key_lower in header_key.lower():
                detected.append(waf_name)
    return list(set(detected))


def detect_tech(body):
    """从 HTML 正文识别技术栈"""
    body_lower = body.lower()
    found = set()
    for keyword, tech_name in TECH_MAP.items():
        if keyword in body_lower:
            found.add(tech_name)
    return sorted(found)


def probe_subdomain(sub):
    """探测单个子域名的 HTTP/HTTPS 服务"""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{sub}"
        try:
            resp = requests.get(
                url, headers=HEADERS, timeout=10,
                allow_redirects=True, verify=False,
            )
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.I | re.S)
            if m:
                title = m.group(1).strip()[:100]

            tech = detect_tech(resp.text[:100000])
            waf = detect_waf(resp.headers)

            return {
                "subdomain": sub,
                "url": resp.url,
                "status": resp.status_code,
                "title": title,
                "server": resp.headers.get("Server", ""),
                "tech": tech,
                "waf": waf,
            }
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue
    return None


def http_probe(subdomains, max_workers=None):
    """批量 HTTP 探测子域名"""
    mw = max_workers or Config.MAX_WORKERS
    log(f"  开始 HTTP 探测 {len(subdomains)} 个子域名...")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=mw) as pool:
        futures = {pool.submit(probe_subdomain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass

    log(f"  HTTP 探测完成，{len(results)} 个可访问", "ok")
    return results


def probe_http_port(host, port):
    """探测指定 IP:Port 的 HTTP 服务（带指纹识别）"""
    scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
    url = f"{scheme}://{host}:{port}"
    result = {"url": url, "status": None, "title": None, "server": None, "tech": [], "waf": []}

    try:
        resp = requests.get(
            url, headers=HEADERS, timeout=Config.TIMEOUT,
            verify=False, allow_redirects=True,
        )
        result["status"] = resp.status_code
        result["server"] = resp.headers.get("Server", "")
        result["final_url"] = resp.url

        m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.I | re.S)
        if m:
            result["title"] = m.group(1).strip()[:100]

        result["tech"] = detect_tech(resp.text[:100000])
        result["waf"] = detect_waf(resp.headers)

    except requests.exceptions.SSLError:
        alt_scheme = "http" if scheme == "https" else "https"
        alt_url = f"{alt_scheme}://{host}:{port}"
        try:
            resp = requests.get(
                alt_url, headers=HEADERS, timeout=Config.TIMEOUT,
                verify=False, allow_redirects=True,
            )
            result["url"] = alt_url
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("Server", "")
            result["final_url"] = resp.url
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.I | re.S)
            if m:
                result["title"] = m.group(1).strip()[:100]
            result["tech"] = detect_tech(resp.text[:100000])
        except Exception:
            pass
    except Exception:
        pass

    return result


def http_probe_ports(targets, open_ports):
    """对开放 HTTP 端口的 IP 进行探测"""
    http_port_set = {
        80, 81, 443, 8080, 8081, 8443, 8888, 9090, 9443,
        3000, 4000, 5000, 7001, 8000, 8008, 8082, 8083,
        8085, 8086, 8088, 8090, 9000, 9080, 4443,
    }
    results = {}

    for host, ports in open_ports.items():
        for port in ports:
            if port not in http_port_set:
                continue
            key = f"{host}:{port}"
            log(f"    探测 {key}...")
            results[key] = probe_http_port(host, port)

            info = results[key]
            status = info.get("status") or "-"
            title = info.get("title") or "-"
            server = info.get("server") or "-"
            tech = ", ".join(info.get("tech", [])) or "-"
            log(f"      状态: {status} | {title}", "ok")
            if info.get("tech"):
                log(f"      指纹: {tech}", "ok")

    return results


# ══════════════════════════════════════════════════════════════
#  模块 8：FOFA 查询
# ══════════════════════════════════════════════════════════════

def fofa_query(domain, email=None, key=None, size=100):
    """FOFA 资产查询"""
    email = email or Config.FOFA_EMAIL
    key = key or Config.FOFA_KEY
    if not email or not key:
        log("  FOFA API 未配置，跳过", "warn")
        return []

    log("  查询 FOFA...")
    try:
        import base64
        query = f'domain="{domain}"'
        qbase64 = base64.b64encode(query.encode()).decode()
        url = (
            f"https://fofa.info/api/v1/search/all"
            f"?email={email}&key={key}&qbase64={qbase64}"
            f"&size={size}&fields=host,ip,port,protocol,server,product"
        )
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("error", False):
                log(f"  FOFA 错误: {data.get('errmsg', '')}", "err")
                return []
            results = data.get("results", [])
            log(f"  FOFA → {len(results)} 条结果", "ok")
            return results
    except Exception as e:
        log(f"  FOFA 查询失败: {e}", "warn")
    return []


# ══════════════════════════════════════════════════════════════
#  模块 9：报告生成
# ══════════════════════════════════════════════════════════════

def generate_report(domain, resolved, all_ips, asn_info, open_ports,
                    services, http_results, fofa_results):
    """生成综合文本报告"""
    report_file = OUTPUT_DIR / f"{domain}_full_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"{'='*70}\n")
        f.write(f"  {domain} 全面资产收集报告\n")
        f.write(f"{'='*70}\n")
        f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # 摘要
        f.write("📊 摘要:\n")
        f.write(f"  子域名总数: {len(resolved)}\n")
        f.write(f"  唯一 IP 数: {len(all_ips)}\n")
        f.write(f"  开放端口数: {sum(len(v) for v in open_ports.values())}\n")
        f.write(f"  HTTP 可访问: {len(http_results)}\n")
        f.write(f"  FOFA 结果: {len(fofa_results)}\n\n")

        # ASN 分布
        if asn_info:
            f.write("ASN / 组织分布:\n")
            orgs = defaultdict(list)
            for info in asn_info:
                orgs[info.get("org", "Unknown")].append(info["ip"])
            for org, ips in sorted(orgs.items(), key=lambda x: -len(x[1])):
                f.write(f"  {org}: {len(ips)} 个 IP\n")
                for ip in sorted(ips)[:5]:
                    f.write(f"    - {ip}\n")
                if len(ips) > 5:
                    f.write(f"    ... 还有 {len(ips) - 5} 个\n")
            f.write("\n")

        # 子域名列表
        f.write(f"🔗 子域名列表 ({len(resolved)} 个):\n")
        for sub in sorted(resolved.keys()):
            ips = ", ".join(resolved[sub])
            f.write(f"  {sub} → {ips}\n")
        f.write("\n")

        # 开放端口
        if open_ports:
            f.write("🔓 开放端口:\n")
            for ip in sorted(open_ports.keys()):
                ports = ", ".join(str(p) for p in sorted(open_ports[ip]))
                f.write(f"  {ip}: {ports}\n")
            f.write("\n")

        # 服务识别
        if services:
            f.write("⚙️  服务识别:\n")
            for svc in sorted(services, key=lambda x: (x["ip"], x["port"])):
                ssl_tag = " [SSL]" if svc["ssl"] else ""
                f.write(f"  {svc['ip']}:{svc['port']} → {svc['service']}{ssl_tag}\n")
                if svc["banner"]:
                    banner = svc["banner"][:100].replace("\n", " ").replace("\r", "")
                    f.write(f"    Banner: {banner}\n")
            f.write("\n")

        # HTTP 结果
        if http_results:
            f.write("🌐 HTTP 服务:\n")
            status_counts = defaultdict(int)
            for r in http_results:
                status_counts[r["status"]] += 1
            f.write("  状态码分布: ")
            f.write(", ".join(f"{code}: {count}个" for code, count in sorted(status_counts.items())))
            f.write("\n\n")

            for r in sorted(http_results, key=lambda x: x["status"]):
                url = r.get("url") or r.get("subdomain", "")
                f.write(f"  [{r['status']}] {url}\n")
                if r.get("title"):
                    f.write(f"    标题: {r['title'][:80]}\n")
                if r.get("server"):
                    f.write(f"    服务器: {r['server']}\n")
                if r.get("tech"):
                    f.write(f"    指纹: {', '.join(r['tech'])}\n")
            f.write("\n")

        # FOFA 结果
        if fofa_results:
            f.write("🔎 FOFA 结果:\n")
            for item in fofa_results[:50]:
                f.write(f"  {item}\n")

    log(f"报告已保存: {report_file}", "ok")
    return report_file


def save_json(data, filename):
    """保存 JSON 到 results 目录"""
    path = OUTPUT_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


# ══════════════════════════════════════════════════════════════
#  模块 10：轻量模式（供 recon.py 调用）
# ══════════════════════════════════════════════════════════════

def run_quick(domain, output_dir=None):
    """
    轻量模式 — 仅做子域名收集 + DNS 解析 + HTTP 探测
    供 recon.py 调用，也支持独立使用
    """
    global OUTPUT_DIR
    if output_dir:
        OUTPUT_DIR = Path(output_dir)
        OUTPUT_DIR.mkdir(exist_ok=True)

    log(f"{'=' * 50}")
    log(f"快速摸底: {domain}")
    log(f"{'=' * 50}")
    start = time.time()

    # 1. 被动收集
    all_subs = collect_passive(domain)

    # 2. DNS 爆破
    brute = brute_force_subdomains(domain)
    for sub, ips in brute.items():
        if sub not in all_subs:
            all_subs.add(sub)

    # 3. DNS 解析验证
    resolved = resolve_all(all_subs)
    all_ips = get_all_ips(resolved)
    log(f"收集到 {len(all_ips)} 个唯一 IP", "ok")

    # 保存子域名结果
    subs_data = {sub: {"ips": ips} for sub, ips in sorted(resolved.items())}
    save_json(subs_data, f"{domain}_subdomains.json")

    # 4. HTTP 探测
    http_results = http_probe(list(resolved.keys()))
    save_json(http_results, f"{domain}_http.json")

    # 快速报告
    report_file = OUTPUT_DIR / f"{domain}_quick_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"{'=' * 60}\n")
        f.write(f"  {domain} 快速资产摸底报告\n")
        f.write(f"{'=' * 60}\n")
        f.write(f"收集时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总子域名: {len(resolved)}\n")
        f.write(f"HTTP 可访问: {len(http_results)}\n\n")

        f.write("--- 子域名列表 ---\n")
        for sub in sorted(resolved.keys()):
            f.write(f"  {sub} -> {', '.join(resolved[sub])}\n")

        f.write("\n--- HTTP 服务 ---\n")
        for r in sorted(http_results, key=lambda x: x["status"]):
            url = r.get("url") or r.get("subdomain", "")
            f.write(f"  [{r['status']}] {url}")
            if r.get("title"):
                f.write(f"  | {r['title'][:60]}")
            if r.get("tech"):
                f.write(f"  | {', '.join(r['tech'][:3])}")
            f.write("\n")

        if http_results:
            status_counts = defaultdict(int)
            for r in http_results:
                status_counts[r["status"]] += 1
            f.write("\n--- 状态码分布 ---\n")
            for code in sorted(status_counts.keys()):
                f.write(f"  {code}: {status_counts[code]} 个\n")

    log(f"快速报告已保存: {report_file}", "ok")
    elapsed = time.time() - start

    # 终端摘要
    print(f"\n{'=' * 60}")
    print(f"  快速摸底完成:")
    print(f"  子域名: {len(resolved)}")
    print(f"  HTTP 可访问: {len(http_results)}")
    print(f"  耗时: {elapsed:.1f} 秒")
    print(f"  结果目录: {OUTPUT_DIR}")
    print(f"{'=' * 60}")

    return resolved, http_results


# ══════════════════════════════════════════════════════════════
#  主流程（全面扫描）
# ══════════════════════════════════════════════════════════════

def load_config(config_path):
    """加载配置文件，返回配置字典"""
    path = Path(config_path)
    if not path.exists():
        log(f"配置文件不存在: {config_path}", "warn")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_full(domain, args):
    """全面扫描 — 对一个域名执行全部收集流程"""
    global OUTPUT_DIR
    Config.MAX_WORKERS = args.workers or 50

    log(f"{'=' * 50}")
    log(f"开始全面收集: {domain}")
    log(f"{'=' * 50}")
    start = time.time()

    # 1. 子域名收集（被动）
    all_subs = collect_passive(domain)

    # 2. DNS 爆破
    brute = brute_force_subdomains(domain)
    for sub, ips in brute.items():
        if sub not in all_subs:
            all_subs.add(sub)

    # 3. DNS 解析
    resolved = resolve_all(all_subs, Config.MAX_WORKERS)
    all_ips = get_all_ips(resolved)
    log(f"收集到 {len(all_ips)} 个唯一 IP", "ok")

    # 保存中间结果
    subs_data = {s: {"ips": ips} for s, ips in sorted(resolved.items())}
    save_json(subs_data, f"{domain}_subdomains.json")

    # 4. ASN 查询
    asn_info = collect_asn_info(all_ips, 10)
    save_json(asn_info, f"{domain}_asn.json")

    # 如果只收集子域名，到这里就结束
    if args.subdomain_only:
        log("--subdomain-only 模式，跳过后续步骤", "info")
        elapsed = time.time() - start
        log(f"收集完成！耗时 {elapsed:.1f} 秒", "ok")
        log(f"结果目录: {OUTPUT_DIR}", "info")
        return

    # 5. 端口扫描
    open_ports = {}
    if not args.skip_portscan and all_ips:
        ports = COMMON_PORTS
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        open_ports = scan_ports(all_ips, ports, 100)
        save_json(open_ports, f"{domain}_ports.json")

    # 6. 服务识别
    services = []
    if not args.skip_service and open_ports:
        services = identify_services(open_ports, 50)
        save_json(services, f"{domain}_services.json")

    # 7. HTTP 探测（子域名）
    http_results = http_probe(list(resolved.keys()), Config.MAX_WORKERS)
    save_json(http_results, f"{domain}_http.json")

    # 8. HTTP 探测（端口）
    if open_ports:
        http_port_results = http_probe_ports(all_ips, open_ports)
        if http_port_results:
            save_json(http_port_results, f"{domain}_http_ports.json")

    # 9. FOFA 查询
    fofa_results = fofa_query(domain, Config.FOFA_EMAIL, Config.FOFA_KEY)

    # 10. 生成报告
    generate_report(domain, resolved, all_ips, asn_info, open_ports,
                    services, http_results, fofa_results)

    elapsed = time.time() - start
    log(f"{'=' * 50}")
    log(f"全量收集完成！耗时 {elapsed:.1f} 秒", "ok")
    log(f"结果目录: {OUTPUT_DIR}", "info")


def main():
    parser = argparse.ArgumentParser(
        description="SRC 资产收集工具 v3 - 综合版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 asset_recon.py example.com\n"
            "  python3 asset_recon.py example.com --skip-portscan\n"
            "  python3 asset_recon.py example.com --quick\n"
            "  python3 asset_recon.py                    # 从 config.json 读取域名\n"
            "  python3 asset_recon.py --batch            # 扫描 config 中所有域名\n"
            "  python3 asset_recon.py --batch --quick    # 快速摸底所有域名\n"
        ),
    )
    parser.add_argument("domain", nargs="?", help="目标域名（留空则从 config.json 读取）")
    parser.add_argument("--config", type=str, default="config.json", help="配置文件路径（默认 config.json）")
    parser.add_argument("--batch", action="store_true", help="批量扫描 config 中所有域名，默认只取第一个")
    parser.add_argument("--quick", action="store_true", help="快速模式（仅子域名 + HTTP）")
    parser.add_argument("--skip-portscan", action="store_true", help="跳过端口扫描")
    parser.add_argument("--skip-service", action="store_true", help="跳过服务识别")
    parser.add_argument("--subdomain-only", action="store_true", help="仅收集子域名")
    parser.add_argument("--ports", type=str, help="自定义端口列表，逗号分隔")
    parser.add_argument("-o", "--output", type=str, help="输出目录（默认 ./results）")
    parser.add_argument("--fofa-email", default="", help="FOFA 邮箱")
    parser.add_argument("--fofa-key", default="", help="FOFA API Key")
    parser.add_argument("--workers", type=int, default=50, help="并发数（默认 50）")
    args = parser.parse_args()

    # 全局配置
    Config.FOFA_EMAIL = args.fofa_email or Config.FOFA_EMAIL
    Config.FOFA_KEY = args.fofa_key or Config.FOFA_KEY
    Config.MAX_WORKERS = args.workers or 50

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
        OUTPUT_DIR.mkdir(exist_ok=True)

    # --- 确定要扫描的域名列表 ---
    domains = []

    if args.domain:
        # 命令行直接指定了域名
        domain = args.domain.strip()
        if domain.startswith("http"):
            domain = re.sub(r"https?://", "", domain).rstrip("/")
        domains = [domain]
    else:
        # 从配置文件读取
        cfg = load_config(args.config)
        if cfg is None:
            log(f"未指定域名，且配置文件 {args.config} 不存在", "err")
            parser.print_help()
            sys.exit(1)
        domains = cfg.get("domains", [])
        if not domains:
            log(f"配置文件中未配置 domains", "err")
            sys.exit(1)
        # 非 batch 模式只取第一个域名
        if not args.batch and len(domains) > 1:
            log(f"配置文件中有 {len(domains)} 个域名，使用 --batch 可扫描全部")
            log(f"本次只扫描第一个: {domains[0]}")
            domains = domains[:1]

    # --- 逐个扫描 ---
    for i, domain in enumerate(domains):
        if i > 0:
            print()  # 多域名间空行分隔

        if args.quick:
            run_quick(domain, str(OUTPUT_DIR))
        else:
            run_full(domain, args)


if __name__ == "__main__":
    main()
