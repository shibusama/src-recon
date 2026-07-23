# SRC-Recon | SRC 资产收集工具集

> 面向 SRC 漏洞挖掘的自动化资产收集工具集，支持子域名枚举、DNS 解析、ASN 查询、端口扫描、服务识别、HTTP 探测和指纹识别。

## 工具列表

| 脚本 | 类型 | 说明 |
|------|------|------|
| `asset_recon.py` | 综合版 | **推荐** — 全部功能：子域名收集 + DNS 爆破 + ASN 查询 + 端口扫描 + 服务识别 + HTTP 探测 + 指纹识别 + FOFA 接口 |
| `recon.py` | 轻量版 | 快速摸底，子域名收集 + HTTP 探测（复用 asset_recon.py） |

## 快速开始

### 环境准备

```bash
pip install dnspython requests pyyaml beautifulsoup4
```

### 方式一：指定域名（最常用）

```bash
# 全面扫描
python3 asset_recon.py example.com

# 快速摸底
python3 recon.py example.com
```

### 方式二：配置文件（批量管理目标）

编辑 `config.json` 放入你的目标列表：

```json
{
  "domains": ["target1.com", "target2.org", "target3.io"],
  "workers": 50
}
```

然后直接运行脚本（无需输入域名）：

```bash
# 扫描 config 中的第一个域名
python3 asset_recon.py

# 扫描 config 中所有域名
python3 asset_recon.py --batch

# 批量快速摸底所有域名
python3 asset_recon.py --batch --quick
python3 recon.py --batch
```

### asset_recon.py（综合版）

```bash
# 全量扫描（推荐）
python3 asset_recon.py example.com

# 从配置文件读取域名
python3 asset_recon.py

# 批量扫描所有配置域名
python3 asset_recon.py --batch

# 快速模式（仅子域名 + HTTP 探测）
python3 asset_recon.py example.com --quick
python3 asset_recon.py --batch --quick

# 跳过端口扫描和服务识别
python3 asset_recon.py example.com --skip-portscan --skip-service

# 仅子域名收集
python3 asset_recon.py example.com --subdomain-only

# 指定端口
python3 asset_recon.py example.com --ports 80,443,8080,8443

# 指定输出目录
python3 asset_recon.py example.com -o ./my_results

# 配置 FOFA API
python3 asset_recon.py example.com --fofa-email your@email.com --fofa-key your_api_key

# 使用自定义配置文件
python3 asset_recon.py --config my_domains.json --batch

# 调整并发数
python3 asset_recon.py example.com --workers 100
```

### recon.py（轻量版 — 快速摸底）

```bash
# 用法同 --quick，适合随手摸一下
python3 recon.py example.com
python3 recon.py              # 从 config.json 读取域名
python3 recon.py --batch      # 批量快速摸底
```

## 功能模块对比

| 功能 | asset_recon.py | recon.py |
|------|:-:|:-:|
| 子域名被动收集（6 源） | ✅ | ✅ |
| DNS 爆破 | ✅ | ✅ |
| DNS 解析验证 | ✅ | ✅ |
| ASN / 组织查询 | ✅ | ❌ |
| 端口扫描 | ✅ | ❌ |
| 服务识别 | ✅ | ❌ |
| HTTP 探测 | ✅ | ✅ |
| 指纹识别（CMS/WAF/框架） | ✅ | ✅ |
| FOFA 接口 | ✅ | ❌ |
| 报告生成 | ✅ | ✅ |

### 各模块说明

**1. 子域名收集（被动）**

通过以下公开数据源被动收集子域名，无需直接扫描目标：

- **crt.sh** — 证书透明度日志
- **HackerTarget** — 被动 DNS 查询
- **RapidDNS** — DNS 记录聚合
- **AlienVault OTX** — 威胁情报平台
- **BufferOver.run** — DNS 数据集
- **DNSDumpster** — DNS 侦察

**2. DNS 解析**

批量解析子域名的 A 记录，验证子域名是否有效，提取所有唯一 IP 地址。

**3. ASN / 组织查询（asset_recon.py 独有）**

通过 ipinfo.io 查询每个 IP 的 ASN 编号、所属组织、国家/城市信息，帮助识别目标的基础设施分布。

**4. 端口扫描**

对收集到的 IP 进行常见端口扫描（默认 60-100+ 个端口），支持自定义端口列表。

**5. 服务识别**

对开放端口进行 Banner 抓取和服务指纹识别，支持 HTTP/HTTPS/FTP/SSH/SMTP/MySQL/Redis/MongoDB 等常见服务。

**6. HTTP 探测**

对所有子域名进行 HTTP/HTTPS 探测，获取状态码、页面标题、Server 头等信息。

**7. 指纹识别**

识别目标使用的 CMS（WordPress、Drupal 等）、Web 框架（Spring、Django、Vue 等）、中间件（Nginx、Tomcat 等）和 WAF（Cloudflare、Akamai 等）。通过响应头和页面内容进行匹配。

**8. FOFA 接口（asset_recon.py 独有）**

支持对接 FOFA API，通过 `domain="example.com"` 语法查询 FOFA 资产库。

## 输出文件

所有结果保存在 `results/` 目录下：

| 文件 | 说明 |
|------|------|
| `{domain}_subdomains.json` | 子域名及对应 IP |
| `{domain}_asn.json` | ASN 和组织信息 |
| `{domain}_ports.json` | 开放端口 |
| `{domain}_services.json` | 服务识别结果 |
| `{domain}_http.json` | HTTP 探测结果（含指纹） |
| `{domain}_http_ports.json` | 基于端口的 HTTP 探测结果 |
| `{domain}_full_report.txt` | 综合文本报告（full 模式） |
| `{domain}_quick_report.txt` | 快速摸底报告（--quick 模式） |

## 项目结构

```
src-recon/
├── README.md
├── .gitignore
├── asset_recon.py              # [推荐] 综合版（全部功能）
├── recon.py                    # 轻量版（复用 asset_recon.py）
└── results/                    # 收集结果输出目录
```

## 使用建议

- **快速摸底** → `python3 recon.py example.com` 或 `python3 asset_recon.py example.com --quick`
- **全面收集** → `python3 asset_recon.py example.com`（端口扫描、服务识别、ASN、FOFA 全开）
- **定向任务** → `python3 asset_recon.py example.com --subdomain-only`（仅看子域名）
- **日常顺手** → 把常用目标写进 `config.json`，然后直接 `python3 recon.py`
- **批量巡检** → 编辑 `config.json` 放入多个目标，`python3 asset_recon.py --batch --quick` 一键跑完

## 注意事项

- 本工具仅供授权的安全测试和 SRC 漏洞挖掘使用
- 请遵守目标网站的 robots.txt 和使用条款
- 端口扫描可能触发安全告警，请在授权范围内使用
- FOFA API 需要自行注册并获取 API Key

## License

MIT
