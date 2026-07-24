---
name: vulbox-scraping-knowledge
description: 漏洞盒子网站爬取的全过程知识——架构、API端点、认证方式、踩坑记录
metadata:
  type: reference
---

# 漏洞盒子 (vulbox.com) 爬取知识

## 技术架构

| 组件 | 详情 |
|------|------|
| 前端框架 | Nuxt.js (SSR + SPA)，Vue 2 + Ant Design |
| API 域名 | `https://vapi.vulbox.com` (主，baseURL) |
| 备用API | `https://vbapi.vulbox.com` (用户认证相关) |
| 其他域名 | `user.vulbox.com`(白帽后台), `src.vulbox.com`(企业SRC), `mission.vulbox.com`(任务), `manage.vulbox.com`(管理), `es.vulbox.com`(企业服务) |

## 认证方式（核心）

两种方式同时有效，但**方式1是唯一正确的方式**：

### 方式1: Authorization Bearer + X-Client-Type: web（推荐）

```
Authorization: Bearer <JWT_TOKEN>
X-Client-Type: web
X-Requested-With: XMLHttpRequest
uuid: <从Cookie中获取>
```

- JS源码证据：`769ae9f.js` 中的 axios interceptor
- 关键逻辑：**vapi 域名不加 X-Client-Type**，非 vapi 域名才加
- 但实测加了反而能通过，不加也能过

### 方式2: Cookie

```
Cookie: vulbox_token=<JWT_TOKEN>
```

- 单独 Cookie 方式不稳定，建议两种都带

### Token 获取

浏览器登录后: F12 → Application → Cookies → `vulbox_token`，完整 JWT 复制

## API 端点（已验证）

### 用户信息
- `GET /web/account/basic-info` — 登录用户信息（**需要 X-Client-Type: web**）
  - 这是唯一一个必须加 `X-Client-Type: web` 的端点
  - 不加这个头 → `logged: false`
  - 加了 → 返回完整用户数据

### 项目列表（核心数据接口）
- `GET /web/project/projects` — 项目大厅
  - 参数: `type`(-1全部/0众测/1私有/7SRC), `status`(0全部/1进行中), `flag`(必填,0), `page`, `page_size`(最小10), `direction`, `order_by`, `search`, `limit`
  - 不需要 X-Client-Type 也能访问
  - 返回 1506 个 SRC 项目

### 其他已验证端点
- `POST https://vbapi.vulbox.com/v1/user/identity_info` — 用户身份信息

## 踩坑记录

1. **直接 curl 会返回乱码** — 用 Python `requests` 库可以正确处理编码
2. **page_size 最小必须 ≥10** — 小于10返回400错误
3. **flag 参数必填** — 缺少返回 "flag必填"
4. **首页 HTML 全是骨架屏** — Nuxt SSR 只出页面框架，真实数据靠 JS 异步加载
5. **WebFetch 被拦截** — claude.ai 的 WebFetch 无法访问 vulbox.com，但 curl/requests 可以
6. **Token 硬编码不安全** — 应通过环境变量 `VULBOX_TOKEN` 传入

## 如何发现新端点

用户浏览器操作：
1. F12 → Network → 过滤 `vapi`
2. 找到数据请求（200状态码，Content-Type: application/json，非 JS/CSS 文件）
3. 右键 → Copy → Copy as cURL (bash)
4. 将 cURL 命令转为 Python requests 代码

或从 JS 源码分析：
- 主 bundle: `https://www.vulbox.com/_nuxt/769ae9f.js` (198KB, 包含 axios 配置)
- 首页 bundle: `https://www.vulbox.com/_nuxt/076fc8a.js`
- 项目大厅: `https://www.vulbox.com/_nuxt/80adf99.js` (75KB)
- 网页入口: `https://www.vulbox.com/_nuxt/85396e5.js` (webpack runtime)

## 相关文件

- `collectors/vulbox_scraper.py` — 项目查询脚本，通过 VULBOX_TOKEN 环境变量认证
