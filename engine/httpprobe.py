#!/usr/bin/env python3
"""
步骤 4：HTTP 探测 + 指纹识别 + JS 分析

用法：
  python3 httpprobe.py example.com
  python3 httpprobe.py example.com -i results/example_com_resolved.json
  python3 httpprobe.py example.com --skip-js
"""
import argparse
import concurrent.futures
import re
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import log, save_json, load_json, HEADERS, TECH_MAP, WAF_HEADERS, OUTPUT_DIR


requests.packages.urllib3.disable_warnings()


# ── 指纹识别 ─────────────────────────────────────────────────

def detect_waf(headers):
    detected = []
    for key_lower, waf_name in WAF_HEADERS.items():
        for header_key in headers:
            if header_key.lower() == key_lower or key_lower in header_key.lower():
                detected.append(waf_name)
    return list(set(detected))


def detect_tech(body):
    body_lower = body.lower()
    found = set()
    for keyword, tech_name in TECH_MAP.items():
        if keyword in body_lower:
            found.add(tech_name)
    return sorted(found)


# ── 子域名 HTTP 探测 ────────────────────────────────────────

def probe_subdomain(sub):
    for scheme in ["https", "http"]:
        url = f"{scheme}://{sub}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=10,
                                allow_redirects=True, verify=False)
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.I | re.S)
            if m:
                title = m.group(1).strip()[:100]
            tech = detect_tech(resp.text[:100000])
            waf = detect_waf(resp.headers)
            return {
                "subdomain": sub, "url": resp.url, "status": resp.status_code,
                "title": title, "server": resp.headers.get("Server", ""),
                "tech": tech, "waf": waf,
            }
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue
    return None


def http_probe(subdomains, max_workers=50):
    log(f"  开始 HTTP 探测 {len(subdomains)} 个子域名...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
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


# ── 端口级 HTTP 探测 ────────────────────────────────────────

def probe_http_port(host, port):
    scheme = "https" if port in (443, 8443, 9443, 4443) else "http"
    url = f"{scheme}://{host}:{port}"
    result = {"url": url, "status": None, "title": None, "server": None, "tech": [], "waf": []}
    try:
        resp = requests.get(url, headers=HEADERS, timeout=5, verify=False, allow_redirects=True)
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
        try:
            resp = requests.get(f"{alt_scheme}://{host}:{port}", headers=HEADERS,
                                timeout=5, verify=False, allow_redirects=True)
            result["url"] = f"{alt_scheme}://{host}:{port}"
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


def http_probe_ports(open_ports):
    http_port_set = {80, 81, 443, 8080, 8081, 8443, 8888, 9090, 9443,
                     3000, 4000, 5000, 7001, 8000, 8008, 8082, 8083,
                     8085, 8086, 8088, 8090, 9000, 9080, 4443}
    results = {}
    for host, ports in open_ports.items():
        for port in ports:
            if port not in http_port_set:
                continue
            results[f"{host}:{port}"] = probe_http_port(host, port)
    log(f"  端口 HTTP 探测完成，{len(results)} 个服务", "ok")
    return results


# ── JS 分析 ──────────────────────────────────────────────────

def analyze_js(url):
    results = {"endpoints": [], "paths": [], "secrets": []}
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        if resp.status_code != 200:
            return results

        html = resp.text
        js_urls = set()
        for m in re.finditer(r'src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]', html, re.I):
            js_url = m.group(1)
            if js_url.startswith("//"):
                js_url = "https:" + js_url
            elif js_url.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
            js_urls.add(js_url)

        all_js = ""
        for js_url in js_urls:
            try:
                r = requests.get(js_url, headers=HEADERS, timeout=10, verify=False)
                if r.status_code == 200:
                    all_js += r.text + "\n"
            except Exception:
                pass

        if not all_js:
            return results

        endpoints = set()
        for m in re.finditer(r'["\'](https?://[^"\']+(?:api|v[1-9]|rest|graphql)[^"\']*)["\']', all_js, re.I):
            endpoints.add(m.group(1))
        for m in re.finditer(r'["\'](wss?://[^"\']+)["\']', all_js):
            endpoints.add(m.group(1))

        paths = set()
        for m in re.finditer(r'["\']((?:/[a-zA-Z0-9_/-]*)?api[a-zA-Z0-9_/-]*)["\']', all_js, re.I):
            paths.add(m.group(1))
        for m in re.finditer(r'baseURL\s*[=:]\s*["\']([^"\']+)["\']', all_js):
            paths.add(m.group(1))

        secrets = set()
        for m in re.finditer(r'["\'][A-Za-z0-9+/=]{20,}["\']', all_js):
            s = m.group(0).strip("\"'")
            if len(s) >= 20 and not s.isdigit():
                secrets.add(s[:50])

        log(f"  JS 分析 → {len(js_urls)} 个文件, {len(endpoints)} 接口, {len(paths)} 路径", "ok")
        return {"endpoints": sorted(endpoints), "paths": sorted(paths), "secrets": sorted(secrets)[:20]}
    except Exception as e:
        log(f"  JS 分析失败: {e}", "warn")
        return results


# ── 主入口 ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="步骤4: HTTP 探测 + 指纹识别 + JS 分析")
    parser.add_argument("domain", help="目标域名")
    parser.add_argument("-i", "--input", help="解析结果文件（默认 results/{domain}_resolved.json）")
    parser.add_argument("--ports", help="端口扫描结果文件（可选，开启端口级 HTTP 探测）")
    parser.add_argument("--skip-js", action="store_true", help="跳过 JS 分析")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    args = parser.parse_args()

    if args.output:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output)
        OUTPUT_DIR.mkdir(exist_ok=True)

    domain = args.domain.strip()
    if domain.startswith("http"):
        domain = re.sub(r"https?://", "", domain).rstrip("/")

    res_file = args.input or f"{domain}_resolved.json"
    data = load_json(res_file)
    if data is None:
        log(f"请先运行 resolve.py {domain}", "err")
        return

    subdomains = list(data.keys())
    log(f"读取到 {len(subdomains)} 个子域名")
    log("=" * 50)

    # HTTP 探测
    http_results = http_probe(subdomains)
    save_json(http_results, f"{domain}_http.json")

    # 端口级 HTTP 探测
    if args.ports:
        ports_data = load_json(args.ports)
        if ports_data:
            http_ports = http_probe_ports(ports_data)
            if http_ports:
                save_json(http_ports, f"{domain}_http_ports.json")

    # JS 分析（对第一个可达站点）
    if not args.skip_js and http_results:
        first = http_results[0]
        first_url = first.get("url") or f"https://{first['subdomain']}"
        js_results = analyze_js(first_url)
        if js_results.get("endpoints") or js_results.get("paths"):
            save_json(js_results, f"{domain}_js_analysis.json")

    log(f"\nHTTP 探测完成: {len(http_results)} 个可访问")


if __name__ == "__main__":
    main()
