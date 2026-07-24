#!/usr/bin/env python3
"""公共模块 — 配置、常量、工具函数"""

import json
import time
from collections import defaultdict
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "results"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# 常见端口
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 389,
    443, 445, 465, 512, 513, 514, 515, 587, 631, 636, 873, 902, 990, 993,
    995, 1025, 1080, 1433, 1434, 1521, 1723, 2049, 2080, 2082, 2083, 2086,
    2087, 2095, 2096, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 4000, 4443,
    5000, 5001, 5432, 5601, 5672, 5900, 5901, 6379, 6443, 7001, 7002, 7077,
    8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
    8087, 8088, 8089, 8090, 8091, 8092, 8093, 8095, 8161, 8443, 8448, 8500,
    8880, 8888, 8983, 9000, 9001, 9080, 9081, 9090, 9091, 9200, 9300, 9443,
    10000, 10250, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 61616,
]

# 常见子域名
COMMON_SUBS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "imap",
    "ns1", "ns2", "dns", "dns1", "dns2",
    "admin", "portal", "login", "sso", "auth", "oauth", "cas", "ldap",
    "console", "dashboard", "panel", "manage", "management",
    "pma", "phpmyadmin", "adminer",
    "api", "app", "web", "mobile", "m", "h5", "webapp", "wx", "mini",
    "dev", "test", "staging", "uat", "prod", "beta", "demo",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "build",
    "jira", "confluence", "wiki", "docs",
    "monitor", "nagios", "zabbix", "prometheus", "grafana", "kibana",
    "elasticsearch", "log", "syslog", "ntp", "backup", "bak",
    "cloud", "aws", "azure", "gcp", "server", "proxy", "gateway",
    "lb", "loadbalancer", "cache", "cdn", "static", "assets",
    "img", "image", "images", "media", "file", "files", "download", "upload",
    "vpn", "remote", "office", "internal", "intranet", "extranet", "corp",
    "sip", "meet", "video", "live", "stream", "chat", "im",
    "email", "mail2", "exchange", "owa", "activesync", "autodiscover",
    "oa", "erp", "crm", "hr", "finance", "pay", "payment",
    "order", "trade", "exchange", "shop", "store", "cart", "checkout",
    "blog", "news", "support", "help", "kb", "forum", "community",
    "security", "sec", "soc", "cert", "waf",
    "data", "database", "db", "mysql", "redis", "bi", "analytics",
    "ai", "ml", "iot", "smart",
    "us", "cn", "eu", "asia", "ap", "jp", "kr", "tw", "hk", "sg",
    "us2", "eu2", "ap2",
    "partner", "affiliate", "reseller", "dealer",
    "training", "learn", "edu", "academy", "event", "events",
    "careers", "job", "jobs", "recruit",
    "service", "services", "notification", "notify", "push",
    "report", "search", "status", "health",
]

# 指纹库
TECH_MAP = {
    "wordpress": "WordPress", "wp-content": "WordPress",
    "wp-json": "WordPress", "wp-includes": "WordPress",
    "drupal": "Drupal", "joomla": "Joomla",
    "thinkphp": "ThinkPHP", "laravel": "Laravel",
    "spring": "Spring Framework", "springboot": "Spring Boot",
    "struts": "Apache Struts",
    "django": "Django", "flask": "Flask", "csrftoken": "Django",
    "express": "Express.js",
    "next.js": "Next.js", "nuxt": "Nuxt.js",
    "vue": "Vue.js", "react": "React", "angular": "Angular",
    "bootstrap": "Bootstrap", "jquery": "jQuery",
    "tomcat": "Apache Tomcat", "weblogic": "WebLogic",
    "jboss": "JBoss", "wildfly": "WildFly",
    "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
    "caddy": "Caddy", "traefik": "Traefik",
    "phpmyadmin": "phpMyAdmin", "adminer": "Adminer",
    "jenkins": "Jenkins", "hudson": "Hudson",
    "grafana": "Grafana", "kibana": "Kibana",
    "prometheus": "Prometheus", "alertmanager": "Alertmanager",
    "swagger": "Swagger UI", "api-docs": "Swagger UI",
    "redoc": "ReDoc", "graphql": "GraphQL",
    "elasticsearch": "Elasticsearch", "cerebro": "Cerebro",
    "redis": "Redis", "redis-commander": "Redis Commander",
    "sentry": "Sentry", "gitlab": "GitLab",
    "rocket.chat": "Rocket.Chat", "mattermost": "Mattermost",
    "php": "PHP",
}

WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai": "Akamai",
    "akamai-": "Akamai",
    "x-cdn": "CDNetworks",
    "x-powered-by-360wzb": "360WAF",
    "x-waf": "Web Application Firewall",
    "server: yunjiasu-nginx": "Baidu Yunjiasu",
}


def log(msg, level="info"):
    prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}.get(level, "[*]")
    print(f"[{time.strftime('%H:%M:%S')}] {prefix} {msg}", flush=True)


def save_json(data, filename):
    path = OUTPUT_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log(f"已保存: {filename}", "ok")
    return path


def load_json(filename):
    path = OUTPUT_DIR / filename
    if not path.exists():
        log(f"文件不存在: {filename}", "err")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_config(config_path="config.json"):
    path = Path(config_path) if not isinstance(config_path, Path) else config_path
    if not path.exists():
        log(f"配置文件不存在: {config_path}", "warn")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)
