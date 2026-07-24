#!/usr/bin/env python3
"""
资产收集工具 — 总调度
按步骤依次执行：收集 → 解析 → 扫描 → HTTP → 历史 → 报告

用法：
  python3 asset_recon.py example.com        # 全流程
  python3 asset_recon.py --quick example.com # 快速摸底
  python3 asset_recon.py --batch             # 批量扫描 config 中所有域名
"""
import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

from common import log, load_config, OUTPUT_DIR


def run_step(step_name, *args):
    """运行一个步骤脚本，传递参数"""
    script = Path(__file__).parent / f"{step_name}.py"
    if not script.exists():
        log(f"步骤脚本不存在: {step_name}.py", "err")
        return False

    cmd = [sys.executable, str(script)] + list(args)
    log(f"执行步骤 {step_name}...")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        log(f"步骤 {step_name} 失败 (code={result.returncode})", "err")
        return False
    return True


def run_quick(domain, output_dir=None, skip_history=False, skip_js=False):
    """快速摸底：collect → resolve → httpprobe"""
    if output_dir:
        OUTPUT_DIR.mkdir(exist_ok=True)

    log("=" * 50)
    log(f"快速摸底: {domain}")
    log("=" * 50)
    start = time.time()

    # 步骤1: 收集
    run_step("collect", domain, "-o", str(OUTPUT_DIR))

    # 步骤2: 解析
    run_step("resolve", domain, "-o", str(OUTPUT_DIR))

    # 步骤4: HTTP 探测 + JS
    httpprobe_args = [domain, "-o", str(OUTPUT_DIR)]
    if skip_js:
        httpprobe_args.append("--skip-js")
    run_step("httpprobe", *httpprobe_args)

    # 步骤5: 历史（可选）
    if not skip_history:
        run_step("history", domain, "--skip-icp", "-o", str(OUTPUT_DIR))

    # 步骤6: 快速报告
    run_step("report", domain, "--quick", "-o", str(OUTPUT_DIR))

    elapsed = time.time() - start
    log(f"快速摸底完成，耗时 {elapsed:.1f} 秒")


def run_full(domain, args):
    """全量扫描：collect → resolve → scan → httpprobe → history → report"""
    if args.output:
        OUTPUT_DIR.mkdir(exist_ok=True)

    log("=" * 50)
    log(f"开始全面收集: {domain}")
    log("=" * 50)
    start = time.time()

    # 步骤1: 收集
    run_step("collect", domain, "-o", str(OUTPUT_DIR))

    # 步骤2: 解析 + ASN
    run_step("resolve", domain, "-o", str(OUTPUT_DIR))

    # 如果只收集子域名，到这结束
    if args.subdomain_only:
        log("--subdomain-only 模式，跳过后续步骤", "ok")
        return

    # 步骤3: 端口扫描 + 服务识别
    scan_args = [domain, "--scanner", args.scanner, "-o", str(OUTPUT_DIR)]
    if args.skip_service:
        scan_args.append("--skip-service")
    if args.ports:
        scan_args.extend(["--ports", args.ports])
    run_step("scan", *scan_args)

    # 步骤4: HTTP 探测
    httpprobe_args = [domain, "-o", str(OUTPUT_DIR)]
    httpprobe_args.extend(["--ports", str(OUTPUT_DIR / f"{domain}_ports.json")])
    if args.skip_js:
        httpprobe_args.append("--skip-js")
    run_step("httpprobe", *httpprobe_args)

    # 步骤5: 历史
    if not args.skip_history:
        history_args = [domain, "-o", str(OUTPUT_DIR)]
        if args.skip_icp:
            history_args.append("--skip-icp")
        run_step("history", *history_args)

    # 步骤6: 报告
    run_step("report", domain, "-o", str(OUTPUT_DIR))

    elapsed = time.time() - start
    log(f"全面收集完成，耗时 {elapsed:.1f} 秒")


def main():
    parser = argparse.ArgumentParser(
        description="SRC 资产收集工具 — 步骤化总调度",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 asset_recon.py example.com\n"
            "  python3 asset_recon.py --quick example.com\n"
            "  python3 asset_recon.py --batch\n"
            "  python3 asset_recon.py --skip-portscan --skip-service\n"
        ),
    )
    parser.add_argument("domain", nargs="?", help="目标域名（留空则从 config.json 读取）")
    parser.add_argument("--config", type=str, default="config.json", help="配置文件路径")
    parser.add_argument("--batch", action="store_true", help="批量扫描 config 中所有域名")
    parser.add_argument("--quick", action="store_true", help="快速模式")
    parser.add_argument("--scanner", choices=["nmap", "thread"], default="nmap", help="端口扫描引擎")
    parser.add_argument("--skip-portscan", action="store_true", help="跳过端口扫描")
    parser.add_argument("--skip-service", action="store_true", help="跳过服务识别")
    parser.add_argument("--skip-history", action="store_true", help="跳过历史记录查询")
    parser.add_argument("--skip-icp", action="store_true", help="跳过 ICP 查询")
    parser.add_argument("--skip-js", action="store_true", help="跳过 JS 分析")
    parser.add_argument("--subdomain-only", action="store_true", help="仅收集子域名")
    parser.add_argument("--ports", type=str, help="自定义端口列表，逗号分隔")
    parser.add_argument("-o", "--output", type=str, help="输出目录")
    parser.add_argument("--workers", type=int, default=50, help="并发数")
    args = parser.parse_args()

    # 确定域名列表
    domains = []

    if args.domain:
        domain = args.domain.strip()
        if domain.startswith("http"):
            domain = re.sub(r"https?://", "", domain).rstrip("/")
        domains = [domain]
    else:
        cfg = load_config(args.config)
        if cfg is None:
            log(f"未指定域名，且配置文件 {args.config} 不存在", "err")
            parser.print_help()
            sys.exit(1)
        domains = cfg.get("domains", [])
        if not domains:
            log("配置文件中未配置 domains", "err")
            sys.exit(1)
        if not args.batch and len(domains) > 1:
            log(f"配置文件中有 {len(domains)} 个域名，使用 --batch 可扫描全部")
            log(f"本次只扫描第一个: {domains[0]}")
            domains = domains[:1]

    # 逐个扫描
    for i, domain in enumerate(domains):
        if i > 0:
            print()

        if args.quick:
            run_quick(domain, str(args.output) if args.output else None,
                      args.skip_history, args.skip_js)
        else:
            # 快速模式下 --skip-portscan 自动启用
            if args.subdomain_only or args.skip_portscan:
                # 手动构建一个"仅收集+解析"的快速模式
                log("=" * 50)
                log(f"子域名收集模式: {domain}")
                log("=" * 50)
                run_step("collect", domain, "-o", str(OUTPUT_DIR))
                run_step("resolve", domain, "-o", str(OUTPUT_DIR))
                log("子域名收集完成")
            else:
                run_full(domain, args)


if __name__ == "__main__":
    main()
