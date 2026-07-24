#!/usr/bin/env python3
"""
SRC 资产收集工具 — 统一入口

默认执行新资产收集流水线（engine/asset.py: 8 步完整资产收集）
--classic 切换到旧版 6 步流水线（含端口扫描）

用法：
  python3 run.py example.com              # 新管线：资产收集 8 步
  python3 run.py --classic example.com    # 旧管线：收集→扫描→探测→报告
  python3 run.py --quick example.com      # 新管线快速模式
  python3 run.py --batch                  # 批量扫描配置中所有域名
"""
import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

from common.utils import log, load_config, OUTPUT_DIR

# 旧管线步骤 → 新文件路径映射
CLASSIC_STEP_MAP = {
    "collect": "collectors/subdomain.py",
    "resolve": "collectors/resolver.py",
    "scan": "collectors/legacy/scan.py",
    "httpprobe": "collectors/httpprobe.py",
    "history": "collectors/history.py",
    "report": "collectors/legacy/report.py",
}


def run_asset_pipeline(domain, quick=False, no_fofa=False, no_js=False, no_reverse=False):
    """新管线：调用 pipeline/asset.py 执行 8 步资产收集"""
    script = Path(__file__).parent / "pipeline" / "asset.py"
    cmd = [sys.executable, str(script), domain]
    if quick:
        cmd.append("--quick")
    if no_fofa:
        cmd.append("--no-fofa")
    if no_js:
        cmd.append("--no-js")
    if no_reverse:
        cmd.append("--no-reverse")

    log("启动资产收集管线...")
    result = subprocess.run(cmd, capture_output=False)
    return result.returncode == 0


# ── 旧管线（保留） ──────────────────────────────────────────

def run_step(step_name, *args):
    """运行一个旧版步骤脚本"""
    rel_path = CLASSIC_STEP_MAP.get(step_name, f"engine/{step_name}.py")
    script = Path(__file__).parent / rel_path
    if not script.exists():
        # 回退到 engine/ 目录
        script = Path(__file__).parent / "engine" / f"{step_name}.py"
        log(f"步骤脚本不存在: engine/{step_name}.py", "err")
        return False

    cmd = [sys.executable, str(script)] + list(args)
    log(f"执行步骤 {step_name}...")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        log(f"步骤 {step_name} 失败 (code={result.returncode})", "err")
        return False
    return True


def run_classic_quick(domain, output_dir=None, skip_history=False, skip_js=False):
    """旧版快速摸底"""
    if output_dir:
        OUTPUT_DIR.mkdir(exist_ok=True)

    log("=" * 50)
    log(f"旧版快速摸底: {domain}")
    log("=" * 50)
    start = time.time()

    run_step("collect", domain, "-o", str(OUTPUT_DIR))
    run_step("resolve", domain, "-o", str(OUTPUT_DIR))

    httpprobe_args = [domain, "-o", str(OUTPUT_DIR)]
    if skip_js:
        httpprobe_args.append("--skip-js")
    run_step("httpprobe", *httpprobe_args)

    if not skip_history:
        run_step("history", domain, "--skip-icp", "-o", str(OUTPUT_DIR))

    run_step("report", domain, "--quick", "-o", str(OUTPUT_DIR))

    elapsed = time.time() - start
    log(f"旧版快速摸底完成，耗时 {elapsed:.1f} 秒")


def run_classic_full(domain, args):
    """旧版全量扫描"""
    if args.output:
        OUTPUT_DIR.mkdir(exist_ok=True)

    log("=" * 50)
    log(f"旧版全面收集: {domain}")
    log("=" * 50)
    start = time.time()

    run_step("collect", domain, "-o", str(OUTPUT_DIR))
    run_step("resolve", domain, "-o", str(OUTPUT_DIR))

    if args.subdomain_only:
        log("--subdomain-only 模式，跳过后续步骤", "ok")
        return

    scan_args = [domain, "--scanner", args.scanner, "-o", str(OUTPUT_DIR)]
    if args.skip_service:
        scan_args.append("--skip-service")
    if args.ports:
        scan_args.extend(["--ports", args.ports])
    run_step("scan", *scan_args)

    httpprobe_args = [domain, "-o", str(OUTPUT_DIR)]
    httpprobe_args.extend(["--ports", str(OUTPUT_DIR / f"{domain}_ports.json")])
    if args.skip_js:
        httpprobe_args.append("--skip-js")
    run_step("httpprobe", *httpprobe_args)

    if not args.skip_history:
        history_args = [domain, "-o", str(OUTPUT_DIR)]
        if args.skip_icp:
            history_args.append("--skip-icp")
        run_step("history", *history_args)

    run_step("report", domain, "-o", str(OUTPUT_DIR))

    elapsed = time.time() - start
    log(f"旧版全面收集完成，耗时 {elapsed:.1f} 秒")


# ── 主入口 ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SRC 资产收集工具 — 统一入口",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 run.py example.com             # 新管线：资产收集 8 步\n"
            "  python3 run.py --classic example.com   # 旧管线：含端口扫描\n"
            "  python3 run.py --quick example.com     # 新管线快速模式\n"
        ),
    )
    parser.add_argument("domain", nargs="?", help="目标域名（留空则从 config.json 读取）")
    parser.add_argument("--config", type=str, default="config.json", help="配置文件路径")
    parser.add_argument("--batch", action="store_true", help="批量扫描 config 中所有域名")

    # 管线选择
    parser.add_argument("--classic", action="store_true", help="使用旧版 6 步管线（含端口扫描）")

    # 新管线选项
    parser.add_argument("--quick", action="store_true", help="快速模式（跳过 FOFA/JS/反查）")
    parser.add_argument("--no-fofa", action="store_true", help="跳过 FOFA 测绘")
    parser.add_argument("--no-js", action="store_true", help="跳过 JS 子域名提取")
    parser.add_argument("--no-reverse", action="store_true", help="跳过 IP 反查旁站")

    # 旧管线选项（保留）
    parser.add_argument("--scanner", choices=["nmap", "thread"], default="nmap", help="端口扫描引擎（旧版）")
    parser.add_argument("--skip-portscan", action="store_true", help="跳过端口扫描（旧版）")
    parser.add_argument("--skip-service", action="store_true", help="跳过服务识别（旧版）")
    parser.add_argument("--skip-history", action="store_true", help="跳过历史记录查询（旧版）")
    parser.add_argument("--skip-icp", action="store_true", help="跳过 ICP 查询（旧版）")
    parser.add_argument("--subdomain-only", action="store_true", help="仅收集子域名（旧版）")
    parser.add_argument("--ports", type=str, help="自定义端口列表，逗号分隔（旧版）")
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

    # 逐个执行
    for i, domain in enumerate(domains):
        if i > 0:
            print()

        if args.classic:
            # ── 旧管线 ──
            if args.quick:
                run_classic_quick(domain, str(args.output) if args.output else None,
                                  args.skip_history, args.skip_js)
            elif args.subdomain_only or args.skip_portscan:
                log("=" * 50)
                log(f"旧版子域名收集模式: {domain}")
                log("=" * 50)
                run_step("collect", domain, "-o", str(OUTPUT_DIR))
                run_step("resolve", domain, "-o", str(OUTPUT_DIR))
                log("子域名收集完成")
            else:
                run_classic_full(domain, args)
        else:
            # ── 新管线 ──
            run_asset_pipeline(
                domain,
                quick=args.quick,
                no_fofa=args.no_fofa,
                no_js=args.no_js,
                no_reverse=args.no_reverse,
            )


if __name__ == "__main__":
    main()
