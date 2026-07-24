# SRC-Recon | SRC 资产收集工具集

> 面向 SRC 漏洞挖掘的自动化资产收集工具集。8 步资产收集流水线。

## 目录结构

```
src-recon/
├── run.py               ← 统一入口
├── config.json          ← 目标域名 + API Key 配置
│
├── pipeline/            ← 流水线编排
│   └── asset.py         ← 8 步资产收集编排器
│
├── collectors/          ← 功能模块
│   ├── subdomain.py     ← 子域名收集（6源 + Subfinder + OneForAll）
│   ├── space.py         ← 空间测绘 + IP 反查（FOFA / Hunter）
│   ├── history.py       ← 历史存档 / DNS历史 / ICP备案
│   ├── resolver.py      ← DNS 解析 + ASN 查询
│   ├── httpprobe.py     ← 存活探测 + 指纹 + JS分析
│   └── legacy/          ← 旧管线（端口扫描 + 报告）
│       ├── scan.py
│       └── report.py
│
├── common/              ← 公共模块
│   └── utils.py         ← 日志 / 文件I/O / 配置 / 常量
│
└── results/             ← 收集结果输出
```

## 快速开始

```bash
pip install dnspython requests

# 新管线：8 步资产收集（无端口扫描）
python run.py example.com

# 快速摸底
python run.py --quick example.com

# 跳过某些步骤
python run.py --no-fofa example.com
python run.py --no-reverse example.com

# 旧管线：含端口扫描（保留兼容）
python run.py --classic example.com
```

## API Key 配置

编辑 `config.json` 填入空间测绘平台的 API Key（无 Key 也能跑，跳过 FOFA 步骤）：

```json
{
  "domains": ["target.com"],
  "fofa_email": "your@email.com",
  "fofa_key": "your_fofa_api_key",
  "hunter_key": "your_hunter_api_key"
}
```

## 新管线 8 步流程

| 步 | 模块 | 功能 |
|:--:|------|------|
| 1 | `collectors/subdomain.py` | 基础子域名收集（crt.sh + HackerTarget + RapidDNS + AlienVault + DNSDumpster + BufferOver + Subfinder + OneForAll + DNS爆破） |
| 2 | `collectors/space.py` | 空间测绘（FOFA domain + cert 搜索，Hunter 备选） |
| 3 | `collectors/history.py` | Wayback Machine 历史存档 → 提取子域名 |
| 4 | `collectors/history.py` | DNS 历史记录 + ICP 备案查询 |
| 5 | `collectors/httpprobe.py` | JS 源码挖掘 → 提取硬编码子域名 |
| 6 | `collectors/resolver.py` + `collectors/space.py` | DNS 批量解析 → IP 反查旁站 **★ 关键捡漏** |
| 7 | `pipeline/asset.py` | 汇总去重 |
| 8 | `collectors/httpprobe.py` | 存活探测 |

### 最终产出

| 文件 | 内容 |
|------|------|
| `results/{domain}_all_assets.json` | 全部去重资产 |
| `results/{domain}_live_targets.txt` | 存活清单 `url [状态码] 标题` |
| `results/{domain}_live_urls.txt` | URL 纯列表（喂给 Dirsearch / Nuclei / Xray） |

## 各模块独立运行

```bash
# 完整管线
python pipeline/asset.py example.com

# 单独子域名收集
python collectors/subdomain.py example.com

# 单独 FOFA 查询
python collectors/space.py domain example.com

# 单独 IP 反查
python collectors/space.py ip 1.2.3.4

# 单独历史记录
python collectors/history.py example.com

# 单独存活探测
python collectors/httpprobe.py example.com
```

## 边界

- 资产收集 = 情报搜集，被动行为
- 反查发现的旁站域名必须核对授权范围，不在范围内禁止测试
- 最终 `live_urls.txt` 才进入主动扫描阶段
