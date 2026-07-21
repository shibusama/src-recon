# SRC-Recon | SRC 资产收集工具集

> 面向 SRC 漏洞挖掘的自动化资产收集工具集，支持子域名枚举、DNS 解析、ASN 查询、端口扫描、服务识别、HTTP 探测和指纹识别。

## 工具列表

| 脚本 | 类型 | 说明 |
|------|------|------|
| `asset_recon.py` | 全面版 | 子域名收集 + DNS 解析 + ASN 查询 + 端口扫描 + 服务识别 + HTTP 探测 + FOFA 接口 |
| `recon.py` | 轻量版 | 专注子域名收集 + HTTP 探测，速度快，适合快速摸底 |
| `asset_collector.py` | 增强版 | 子域名收集 + DNS 解析 + 端口扫描 + HTTP 探测 + 指纹识别（含 CMS/WAF/框架识别） |

## 快速开始

### 环境准备

```bash
pip install dnspython requests pyyaml beautifulsoup4
```

### asset_recon.py（全面版）

```bash
# 基础用法
python3 asset_recon.py example.com

# 快速模式（跳过端口扫描和服务识别）
python3 asset_recon.py example.com --skip-portscan --skip-service

# 指定端口
python3 asset_recon.py example.com --ports 80,443,8080,8443

# 配置 FOFA API
python3 asset_recon.py example.com --fofa-email your@email.com --fofa-key your_api_key

# 调整并发数
python3 asset_recon.py example.com --workers 100
```

### recon.py（轻量版）

```bash
python3 recon.py example.com
```

### asset_collector.py（增强版）

```bash
# 基础用法
python3 asset_collector.py -d example.com

# 指定输出目录
python3 asset_collector.py -d example.com -o ./output

# 仅子域名收集
python3 asset_collector.py -d example.com --subdomain-only

# 指定端口范围
python3 asset_collector.py -d example.com --ports 80,443,8080
```

## 功能模块对比

| 功能 | asset_recon.py | recon.py | asset_collector.py |
|------|:-:|:-:|:-:|
| 子域名被动收集 | ✅ | ✅ | ✅ |
| DNS 爆破 | ✅ | ✅ | ✅ |
| DNS 解析验证 | ✅ | ✅ | ✅ |
| ASN / 组织查询 | ✅ | ❌ | ❌ |
| 端口扫描 | ✅ | ❌ | ✅ |
| 服务识别 | ✅ | ❌ | ✅ |
| HTTP 探测 | ✅ | ✅ | ✅ |
| 指纹识别（CMS/WAF） | ❌ | ❌ | ✅ |
| FOFA 接口 | ✅ | ❌ | ❌ |
| 报告生成 | ✅ | ✅ | ✅ |

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

**7. 指纹识别（asset_collector.py 独有）**

识别目标使用的 CMS（WordPress、Drupal 等）、WAF（Cloudflare、Akamai 等）、Web 框架和中间件。

**8. FOFA 接口（asset_recon.py 独有）**

支持对接 FOFA API，通过 `domain="example.com"` 语法查询 FOFA 资产库。

## 输出文件

所有结果保存在 `results/` 目录下：

| 文件 | 说明 |
|------|------|
| `{domain}_subdomains.json` | 子域名及对应 IP |
| `{domain}_asn.json` | ASN 和组织信息（asset_recon.py） |
| `{domain}_ports.json` | 开放端口 |
| `{domain}_services.json` | 服务识别结果 |
| `{domain}_http.json` | HTTP 探测结果 |
| `{domain}_full_report.txt` | 综合文本报告 |
| `{domain}_report.txt` | 轻量版报告（recon.py） |
| `{domain}_assets_table.html` | HTML 分类表格报告 |

## 项目结构

```
src-recon/
├── README.md
├── .gitignore
├── asset_collector.py          # 增强版（含指纹识别）
└── lenovo-recon/
    ├── asset_recon.py          # 全面版（含 ASN/FOFA）
    ├── recon.py                # 轻量版
    ── results/                # 收集结果输出目录
```

## 使用建议

- **快速摸底** → 用 `recon.py`，速度快，几分钟出结果
- **全面收集** → 用 `asset_recon.py`，覆盖 ASN、端口、服务、FOFA
- **深度探测** → 用 `asset_collector.py`，额外提供 CMS/WAF 指纹识别
- **组合使用** → 先用 `recon.py` 快速摸底，再用 `asset_recon.py` 深入扫描

## 注意事项

- 本工具仅供授权的安全测试和 SRC 漏洞挖掘使用
- 请遵守目标网站的 robots.txt 和使用条款
- 端口扫描可能触发安全告警，请在授权范围内使用
- FOFA API 需要自行注册并获取 API Key

## License

MIT
