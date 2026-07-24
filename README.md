# SRC-Recon | SRC 资产收集工具集

> 面向 SRC 漏洞挖掘的自动化资产收集工具集。按步骤拆分，每一步可独立运行。

## 项目结构

```
src-recon/
├── asset_recon.py     ← 总调度：一键执行所有步骤
├── recon.py           ← 轻量版入口（快速摸底）
├── config.json        ← 目标域名配置文件
│
├── common.py          ← 公共模块（配置/常量/工具函数）
├── collect.py         ← 步骤1：子域名收集
├── resolve.py         ← 步骤2：DNS解析 + ASN查询
├── scan.py            ← 步骤3：端口扫描 + 服务识别
├── httpprobe.py       ← 步骤4：HTTP探测 + 指纹 + JS分析
├── history.py         ← 步骤5：历史记录（Wayback/DNS历史/ICP）
├── report.py          ← 步骤6：报告生成（TXT + HTML）
│
└── results/           ← 扫描结果输出目录
```

## 快速开始

### 环境准备

```bash
pip install dnspython requests pyyaml beautifulsoup4
# 如需 nmap 引擎：pip install python-nmap（同时也需要安装 nmap 本体）
```

### 方式一：指定域名

```bash
# 全流程一键扫描
python3 asset_recon.py example.com

# 快速摸底（只跑 1→2→4→6，约2分钟）
python3 asset_recon.py --quick example.com
python3 recon.py example.com
```

### 方式二：配置文件

编辑 `config.json` 放入目标列表：

```json
{
  "domains": ["target1.com", "target2.org"],
  "workers": 50
}
```

然后直接运行：

```bash
python3 asset_recon.py              # 扫描第一个域名
python3 asset_recon.py --batch      # 扫描所有域名
```

### 方式三：单步执行

每一步可独立运行，上一步的输出自动作为下一步的输入：

```bash
python3 collect.py example.com      # 1. 只要子域名
python3 resolve.py example.com      # 2. 只做DNS解析
python3 scan.py example.com         # 3. 只扫端口
python3 httpprobe.py example.com    # 4. 只做HTTP探测
python3 history.py example.com      # 5. 只查历史记录
python3 report.py example.com       # 6. 只生成报告
```

## 执行步骤详解

| 步骤 | 脚本 | 功能 | 输入 | 输出 |
|:----:|------|------|------|------|
| 1 | `collect.py` | 子域名收集（6被动源 + DNS爆破） | 域名 | subdomains.json |
| 2 | `resolve.py` | DNS解析 + ASN组织查询 | subdomains | resolved.json, ips.json, asn.json |
| 3 | `scan.py` | 端口扫描（nmap/threading）+ 服务识别 | ips | ports.json, services.json |
| 4 | `httpprobe.py` | HTTP探测 + 指纹识别 + JS自动分析 | resolved | http.json, js_analysis.json |
| 5 | `history.py` | Wayback历史/DNS历史/ICP备案 | 域名 | wayback.json, dns_history.json |
| 6 | `report.py` | TXT + HTML 报告生成 | 各JSON | report.txt, report.html |

### 步骤1：子域名收集

通过以下 6 个公开数据源被动收集 + DNS 爆破：

- **crt.sh** — 证书透明度日志
- **HackerTarget** — 被动 DNS 查询
- **RapidDNS** — DNS 记录聚合
- **AlienVault OTX** — 威胁情报平台
- **DNSDumpster** — DNS 侦察
- **BufferOver.run** — DNS 数据集
- **DNS爆破** — 183 个常见子域名字典

### 步骤2：DNS 解析 + ASN

批量解析 A 记录，提取唯一 IP，通过 ipinfo.io 查询 ASN/组织归属。

### 步骤3：端口扫描 + 服务识别

双引擎可选：

```bash
python3 scan.py example.com --scanner nmap     # nmap SYN半开扫描（默认，痕迹少）
python3 scan.py example.com --scanner thread    # Python TCP扫描（免装）
```

对开放端口进行 Banner 抓取，识别 MySQL/Redis/Nginx/Tomcat 等服务。

### 步骤4：HTTP 探测 + 指纹 + JS 分析

- 每个子域名检测 HTTP/HTTPS 状态码、标题、Server 头
- 识别 CMS（WordPress/Drupal）、框架（Spring/Vue）、WAF（Cloudflare/Akamai）
- **自动下载并分析 JS 文件**，提取隐藏 API 接口、WebSocket 地址、密钥

### 步骤5：历史记录

- **Wayback Machine** — 找回下线站点的旧路径、旧接口
- **DNS历史** — SecurityTrails/ViewDNS 查历史解析 IP
- **ICP备案** — 查同一主体下的其他域名

### 步骤6：报告生成

同时输出 TXT + HTML 自包含报告，HTML 可直接浏览器打开。

## 参数说明

```bash
python3 asset_recon.py [域名] [选项]

选项：
  --quick                    快速模式（跳过端口扫描/服务识别/部分历史）
  --batch                    批量扫描 config 中所有域名
  --scanner {nmap,thread}    端口扫描引擎（默认 nmap）
  --skip-portscan            跳过端口扫描
  --skip-service             跳过服务识别
  --skip-history             跳过历史记录查询
  --skip-js                  跳过 JS 分析
  --skip-icp                 跳过 ICP 备案查询
  --subdomain-only           仅收集子域名
  --ports PORTS              自定义端口列表（逗号分隔）
  -o, --output OUTPUT        输出目录（默认 ./results）
  --workers WORKERS          并发数（默认 50）
```

## 使用建议

- **快速摸底** → `python3 recon.py example.com` 或 `python3 asset_recon.py --quick example.com`
- **全面收集** → `python3 asset_recon.py example.com`（端口扫描、服务识别、历史记录全开）
- **定向任务** → `python3 collect.py example.com`（只要子域名）
- **日常顺手** → 把常用目标写进 `config.json`，直接 `python3 asset_recon.py`
- **批量巡检** → `python3 asset_recon.py --batch --quick` 一键跑完所有目标

## 注意事项

- 本工具仅供授权的安全测试和 SRC 漏洞挖掘使用
- 请遵守目标网站的 robots.txt 和使用条款
- 端口扫描可能触发安全告警，请在授权范围内使用

## License

MIT
