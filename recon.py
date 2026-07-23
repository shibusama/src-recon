#!/usr/bin/env python3
"""
资产收集工具 - 轻量版（快速摸底）
完全复用 asset_recon.py，零重复代码。

功能：子域名收集（6 被动源 + DNS 爆破）/ DNS 解析 / HTTP 探测 + 指纹识别
用法：
  python3 recon.py example.com     # 指定域名
  python3 recon.py                  # 从 config.json 读取域名
  python3 recon.py --config my.json # 指定配置文件
  python3 recon.py --batch          # 扫描配置中所有域名
"""
import sys
from pathlib import Path
from asset_recon import run_quick, load_config, log

DEFAULT_CONFIG = Path(__file__).parent / "config.json"

if __name__ == "__main__":
    # 简单解析参数（避免重复 argparse）
    args = sys.argv[1:]
    config_path = DEFAULT_CONFIG
    batch = False

    # 剥出 --config 和 --batch
    if "--config" in args:
        idx = args.index("--config")
        if idx + 1 < len(args):
            config_path = Path(args[idx + 1])
            args = args[:idx] + args[idx + 2:]
        else:
            args.remove("--config")

    if "--batch" in args:
        batch = True
        args.remove("--batch")

    # 确定域名
    if args:
        # 命令行指定了域名
        domains = [args[0]]
    else:
        # 从配置文件读取
        cfg = load_config(config_path)
        if cfg is None:
            log(f"未指定域名，且配置文件 {config_path} 不存在", "err")
            sys.exit(1)
        domains = cfg.get("domains", [])
        if not domains:
            log("配置文件中未配置 domains", "err")
            sys.exit(1)
        if not batch and len(domains) > 1:
            log(f"配置文件中有 {len(domains)} 个域名，使用 --batch 可扫描全部")
            log(f"本次只扫描第一个: {domains[0]}")
            domains = domains[:1]

    # 逐个快速摸底
    for i, domain in enumerate(domains):
        if i > 0:
            print()
        run_quick(domain)
