#!/usr/bin/env python3
"""
步骤 3：端口扫描 + 服务识别 — nmap 引擎 / threading 引擎

用法：
  python3 scan.py example.com
  python3 scan.py example.com --scanner nmap
  python3 scan.py example.com -i results/example_com_ips.json
"""
import argparse
import concurrent.futures
import socket
import ssl
import sys
from collections import defaultdict
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import log, save_json, load_json, COMMON_PORTS, OUTPUT_DIR


requests.packages.urllib3.disable_warnings()

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


# ── nmap 扫描 ───────────────────────────────────────────────

def check_nmap():
    """检查 python-nmap 和 nmap 二进制是否可用"""
    try:
        import nmap
        try:
            nmap.PortScanner().nmap_version()
            return True
        except Exception:
            common_paths = [
                r"C:\Program Files (x86)\Nmap",
                r"C:\Program Files\Nmap",
                "/usr/bin", "/usr/local/bin",
            ]
            for p in common_paths:
                if Path(p, "nmap").exists() or Path(p, "nmap.exe").exists():
                    import os
                    os.environ["PATH"] = str(p) + os.pathsep + os.environ.get("PATH", "")
                    return True
            return False
    except ImportError:
        return False


def scan_ports_nmap(ips, ports=None):
    ports = ports or COMMON_PORTS
    if not check_nmap():
        log("  python-nmap 未安装，回退到线程扫描", "warn")
        return scan_ports(ips, ports)

    import nmap
    log(f"  使用 nmap 扫描 {len(ips)} 个 IP × {len(ports)} 个端口...")
    port_str = ",".join(str(p) for p in ports)
    nm = nmap.PortScanner()
    open_ports = defaultdict(list)

    for ip in ips:
        try:
            result = nm.scan(hosts=ip, ports=port_str, arguments="-sS --open -T4")
            if ip not in result.get("scan", {}):
                continue
            host_data = result["scan"][ip]
            for proto in host_data.get("tcp", {}):
                port_data = host_data["tcp"][proto]
                if port_data.get("state") == "open":
                    open_ports[ip].append(int(proto))
        except Exception as e:
            log(f"    nmap 扫描 {ip} 失败: {e}", "warn")
            continue

    total_open = sum(len(v) for v in open_ports.values())
    log(f"  nmap 扫描完成，{total_open} 个开放端口", "ok")
    return dict(open_ports)


# ── threading 扫描 ──────────────────────────────────────────

def scan_port(ip, port, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ips, ports=None, max_workers=100):
    ports = ports or COMMON_PORTS
    log(f"  开始线程扫描 {len(ips)} 个 IP × {len(ports)} 个端口...")
    open_ports = defaultdict(list)
    total = len(ips) * len(ports)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_port, ip, p): (ip, p) for ip in ips for p in ports}
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

    log(f"  线程扫描完成，{sum(len(v) for v in open_ports.values())} 个开放端口", "ok")
    return dict(open_ports)


# ── 服务识别 ─────────────────────────────────────────────────

def identify_service(ip, port, timeout=5):
    info = {"ip": ip, "port": port, "service": SERVICE_PORTS.get(port, "Unknown"), "banner": "", "ssl": False}

    # SSL
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
        info["ssl"] = True
        info["banner"] = banner[:300]
        import re
        m = re.search(r"Server:\s*(.+?)[\r\n]", banner)
        if m:
            info["service"] = m.group(1).strip()
        return info
    except Exception:
        pass

    # TCP
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        payloads = {25: b"EHLO test\r\n", 6379: b"INFO\r\n"}
        payload = payloads.get(port, b"GET / HTTP/1.0\r\n\r\n")
        sock.send(payload)
        banner = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()
        info["banner"] = banner[:300]
        import re
        m = re.search(r"Server:\s*(.+?)[\r\n]", banner)
        if m:
            info["service"] = m.group(1).strip()
        return info
    except Exception:
        return info


def identify_services(open_ports, max_workers=50):
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


# ── 主入口 ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="步骤3: 端口扫描 + 服务识别")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("-i", "--input", help="IP 列表文件（默认 results/{domain}_ips.json）")
    parser.add_argument("--scanner", choices=["nmap", "thread"], default="nmap", help="扫描引擎")
    parser.add_argument("--skip-service", action="store_true", help="跳过服务识别")
    parser.add_argument("--ports", type=str, help="自定义端口列表，逗号分隔")
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

    ip_file = args.input or f"{domain}_ips.json"
    ips = load_json(ip_file)
    if ips is None:
        log(f"请先运行 resolve.py {domain}", "err")
        return

    log(f"读取到 {len(ips)} 个 IP")
    log("=" * 50)

    ports = COMMON_PORTS
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]

    # 端口扫描
    if args.scanner == "nmap":
        open_ports = scan_ports_nmap(ips, ports)
    else:
        open_ports = scan_ports(ips, ports, 100)

    save_json(open_ports, f"{domain}_ports.json")

    # 服务识别
    if not args.skip_service and open_ports:
        services = identify_services(open_ports, 50)
        save_json(services, f"{domain}_services.json")

    total_open = sum(len(v) for v in open_ports.values())
    log(f"\n扫描完成: {total_open} 个开放端口")


if __name__ == "__main__":
    main()
