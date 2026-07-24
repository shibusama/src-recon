#!/usr/bin/env python3
"""
漏洞盒子 (vulbox.com) 数据查询工具
按需查询，不做批量爬取。

使用方法:
  python vulbox_scraper.py                    # 查首页 10 个项目
  python vulbox_scraper.py --search 联想       # 按关键词搜索
  python vulbox_scraper.py --page 1 --size 20  # 指定页数

Token 需定期更新（浏览器 F12 → Application → Cookies → vulbox_token）
"""

import argparse
import time
import os
import requests

BASE = "https://vapi.vulbox.com"

# Token 从环境变量读取，不硬编码
TOKEN = os.environ.get("VULBOX_TOKEN")
if not TOKEN:
    print("[!] 请先设置环境变量 VULBOX_TOKEN")
    print("    Windows: set VULBOX_TOKEN=你的token值")
    print("    获取Token: 浏览器登录漏洞盒子 → F12 → Application → Cookies → vulbox_token")
    exit(1)

UUID = "jxy0vqNGcRkA3PiHLfDMGIz"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Origin": "https://www.vulbox.com",
    "Referer": "https://www.vulbox.com/",
    "X-Client-Type": "web",
    "X-Requested-With": "XMLHttpRequest",
    "uuid": UUID,
    "Accept": "application/json, text/plain, */*",
}
COOKIES = {"vulbox_token": TOKEN, "uuid": UUID, "VB_INDEX_LAYOUT": "default"}


# ── 单次查询（不做批量翻页） ──────────────────────────────

def search_projects(search="", page=1, page_size=10, project_type=-1, status=0):
    """按条件查询项目（单次请求，不翻页）"""
    resp = requests.get(
        f"{BASE}/web/project/projects",
        params={
            "type": project_type, "status": status, "flag": 0,
            "search": search, "page": page, "page_size": page_size,
            "direction": "desc", "order_by": "normal", "limit": "",
        },
        headers=HEADERS, cookies=COOKIES,
    )
    data = resp.json()
    if data.get("code") == 200:
        return data["data"]
    print(f"[!] 请求失败: {data}")
    return None


def print_projects(data):
    """格式化输出项目"""
    if not data or not data.get("data"):
        print("无结果")
        return
    print(f"共 {data['total']} 个项目，当前第 {data['current_page']}/{data['last_page']} 页\n")
    for p in data["data"]:
        bonus = p.get("bonus_range", {})
        print(f"  [{p['id']}] {p['task_title']}")
        print(f"      {p['task_desc']}  |  {p.get('difficult_name', '?')}")
        print(f"      赏金: L{bonus.get('low_min',0)}-{bonus.get('low_max',0)}  "
              f"M{bonus.get('middle_min',0)}-{bonus.get('middle_max',0)}  "
              f"H{bonus.get('high_min',0)}-{bonus.get('high_max',0)}  "
              f"S{bonus.get('serious_min',0)}-{bonus.get('serious_max',0)}")
        goto = p.get("task_website") or p.get("goto") or "-"
        print(f"      {goto}")
        print()


# ── 用户信息 ────────────────────────────────────────────

def get_user_info():
    """查询当前登录用户信息（一次请求）"""
    resp = requests.get(
        f"{BASE}/web/account/basic-info",
        headers=HEADERS, cookies=COOKIES,
    )
    data = resp.json()
    if data.get("code") == 200 and data["data"].get("logged"):
        u = data["data"]["user"]
        print(f"  用户: {u['username']} (uid={u['uid']}, type={u['type']})")
        print(f"  手机: {u['mobile']}")
        lev = data["data"]["level"]
        print(f"  等级: {lev['name']} (经验 {lev['exp_cur']}/{lev['exp_max']})")
        return data["data"]
    print(f"  未登录或 Token 已过期")
    return None


# ── 入口 ────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="漏洞盒子项目查询工具")
    parser.add_argument("--search", "-s", default="", help="搜索关键词")
    parser.add_argument("--page", "-p", type=int, default=1, help="页码 (默认1)")
    parser.add_argument("--size", "-n", type=int, default=10, help="每页数量 (默认10, 最小10)")
    parser.add_argument("--user", "-u", action="store_true", help="查看登录用户信息")
    args = parser.parse_args()

    # 最小 page_size 为 10（API 要求）
    args.size = max(args.size, 10)

    if args.user:
        get_user_info()
    else:
        print(f"[*] 查询: page={args.page}, size={args.size}, search='{args.search}'\n")
        result = search_projects(search=args.search, page=args.page, page_size=args.size)
        print_projects(result)
