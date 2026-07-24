# SRC-Recon | SRC 资产收集工具集

> 面向 SRC 漏洞挖掘的自动化资产收集工具集。  
> **8 步资产收集流水线** → 输出存活资产清单，喂给扫描器。

---

## 目录结构

```
src-recon/
├── run.py                  ← 统一入口
├── config.json             ← 目标域名 + API Key 配置
├── requirements.txt
├── README.md
├── TODO.md                 ← 后续功能规划
│
├── pipeline/               ← 流水线编排
│   └── asset.py            ← 8 步资产收集编排器
│
├── collectors/             ← 功能模块
│   ├── subdomain.py        ← 子域名收集（6源 + Subfinder + OneForAll）
│   ├── space.py            ← 空间测绘 + IP 反查（FOFA / Hunter）
│   ├── history.py          ← 历史存档 / DNS历史 / ICP备案
│   ├── resolver.py         ← DNS 解析 + ASN 查询
│   ├── httpprobe.py        ← 存活探测 + 指纹 + JS子域名提取
│   └── legacy/             ← 旧管线（端口扫描 + 报告，保留兼容）
│       ├── scan.py
│       └── report.py
│
├── common/                 ← 公共模块
│   └── utils.py            ← 日志 / 文件I/O / 配置加载 / 常量
│
├── engine/                 ← 旧版引擎（向下兼容，新代码用 collectors/）
│   ├── common.py
│   ├── collect.py
│   ├── fofa.py
│   ├── history.py
│   ├── resolve.py
│   ├── httpprobe.py
│   ├── scan.py
│   ├── report.py
│   └── asset.py
│
└── results/                ← 资产收集结果输出（gitignore）
```

---

## 快速开始

### 环境准备

```bash
pip install dnspython requests

# 如需旧管线端口扫描：
pip install python-nmap        # + 自行安装 nmap 本体
```

### 新管线：资产收集 8 步（默认）

```bash
# 完整收集（8 步全跑）
python run.py example.com

# 快速摸底（跳过 FOFA / JS / 反查，约 2-4 分钟）
python run.py --quick example.com

# 选择性跳过某步
python run.py --no-fofa example.com      # 跳过 FOFA 测绘
python run.py --no-js example.com        # 跳过 JS 子域名提取
python run.py --no-reverse example.com   # 跳过 IP 反查旁站
```

### 旧管线：含端口扫描（保留兼容）

```bash
python run.py --classic example.com
python run.py --classic --quick example.com
python run.py --classic --subdomain-only example.com   # 只收集子域名
```

### 批量模式

编辑 `config.json` 放入目标列表：

```json
{
  "domains": ["target1.com", "target2.org"],
  "fofa_email": "your@email.com",
  "fofa_key": "your_fofa_api_key",
  "hunter_key": "your_hunter_api_key"
}
```

```bash
python run.py                    # 新管线 - 扫描第一个域名
python run.py --batch            # 新管线 - 扫描全部域名
python run.py --classic --batch  # 旧管线 - 批量
```

### Windows 注意

此环境下 `python3` 指向 Windows Store 重定向器，请用 `python` 代替：

```bash
python run.py example.com        # ✅ 正确
python3 run.py example.com       # ❌ 可能打不开
```

---

## 新管线 8 步流程详解

| 步 | 模块 | 功能 | 关键产出 |
|:--:|------|------|----------|
| 1 | `collectors/subdomain.py` | 基础子域名收集：6 个公开 API 源 + **Subfinder**(30+源) + **OneForAll**(几十源) + DNS 爆破 | 子域名清单 |
| 2 | `collectors/space.py` | 空间测绘补充：FOFA `domain=` + `cert=` 双语法搜索，Hunter 备选 | 测绘子域名 |
| 3 | `collectors/history.py` | Wayback Machine 历史存档 → 提取历史子域名 | 历史子域名 |
| 4 | `collectors/history.py` | DNS 历史记录 + ICP 备案查询 | 备案信息（参考） |
| 5 | `collectors/httpprobe.py` | 存活站点 JS 源码挖掘 → 提取硬编码子域名 ★ | JS 子域名 |
| 6 | `collectors/resolver.py` + `collectors/space.py` | DNS 批量解析 → **IP 反查旁站** ★ 关键捡漏 | 旁站子域名 |
| 7 | `pipeline/asset.py` | 全来源汇总去重 + 过滤泛域名 | `all_assets.json` |
| 8 | `collectors/httpprobe.py` | 存活探测（HTTP 状态码 + 标题 + Server） | `live_targets.txt` |

### 最终产出文件

| 文件 | 格式 | 用途 |
|------|------|------|
| `results/{domain}_all_assets.json` | JSON | 全部去重资产列表 |
| `results/{domain}_live_targets.txt` | 文本 | 存活站点 `url [状态码] 标题` |
| `results/{domain}_live_urls.txt` | 文本 | **URL 纯列表，喂给 Dirsearch / Nuclei / Xray** |

### 各步骤中间产出（供调试用）

| 步骤 | 产出文件 |
|:----:|----------|
| 1 | `{domain}_subdomains.json`, `{domain}_subdomains_detail.json` |
| 2 | `{domain}_fofa_subdomains.json`（有 API Key 时） |
| 3 | `{domain}_wayback_subdomains.json` |
| 5 | `{domain}_js_subdomains.json` |
| 6 | `{domain}_resolved.json`, `{domain}_ips.json`, `{domain}_reverse_subdomains.json` |
| 8 | `{domain}_live.json` |

---

## 各模块独立运行

```bash
# 完整管线
python pipeline/asset.py example.com
python pipeline/asset.py example.com --quick
python pipeline/asset.py example.com --no-fofa

# 单独子域名收集
python collectors/subdomain.py example.com

# 单独 FOFA 查询
python collectors/space.py domain example.com

# 单独 IP 反查
python collectors/space.py ip 1.2.3.4

# 单独历史记录
python collectors/history.py example.com

# 单独存活探测（需先跑 subdomain + resolver）
python collectors/httpprobe.py example.com

# 旧管线单步
python collectors/legacy/scan.py example.com
```

---

## API Key 配置

需要申请对应平台账号获取 API Key，填入 `config.json`：

| 平台 | 配置字段 | 注册地址 |
|------|----------|----------|
| FOFA | `fofa_email` + `fofa_key` | https://fofa.info |
| Hunter 鹰图 | `hunter_key` | https://hunter.qianxin.com |

**无 Key 也能跑**：系统会自动跳过 FOFA 步骤，不影响其他 7 步。

---

## 边界提醒

1. **资产收集 = 情报搜集**，属于被动行为，不直接触碰目标系统
2. 所有搜集出来的资产，必须核对 SRC 官方授权范围，不在清单内禁止探测
3. 步骤 6 反查发现的**旁站域名**尤其容易超出范围，务必核查
4. `live_urls.txt` 是**分水岭**：到此为止是资产收集，之后是主动扫描
5. 拿到 `live_urls.txt` 后，再用外部工具做端口扫描/目录扫描/漏洞扫描

---

## TODO

见 [TODO.md](TODO.md) —— 后续主动探测阶段的规划（端口扫描、目录扫描、漏洞扫描等），尚未实现。
