#!/usr/bin/env python3
"""内置检测规则种子数据"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.rule import DetectionRule


RULES = [
    {
        "rule_code": "WEB_SQLI_001",
        "rule_name": "SQL 注入特征检测",
        "category": "web",
        "attack_type": "SQL Injection",
        "severity": "high",
        "rule_pattern": r"(?i)(union\s+select|or\s+1=1|sleep\s*\(|extractvalue|updatexml|';/\*|--|#|into\s+outfile)",
        "stage_code": "exploit_attempt",
        "description": "检测常见 SQL 注入特征，包括联合查询、布尔盲注、延时注入等",
    },
    {
        "rule_code": "WEB_XSS_001",
        "rule_name": "XSS 特征检测",
        "category": "web",
        "attack_type": "XSS",
        "severity": "medium",
        "rule_pattern": r"(?i)(<script|alert\(|onerror=|onload=|javascript:|<img\s+src|xss)",
        "stage_code": "exploit_attempt",
        "description": "检测反射型 XSS 和存储型 XSS 常见 Payload",
    },
    {
        "rule_code": "WEB_PATH_001",
        "rule_name": "路径穿越检测",
        "category": "web",
        "attack_type": "Path Traversal",
        "severity": "high",
        "rule_pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\|..%252f)",
        "stage_code": "exploit_attempt",
        "description": "检测路径穿越攻击特征",
    },
    {
        "rule_code": "WEB_RCE_001",
        "rule_name": "命令执行特征检测",
        "category": "web",
        "attack_type": "Command Injection",
        "severity": "critical",
        "rule_pattern": r"(?i)(;\s*(ls|cat|id|whoami|pwd|dir|cmd|powershell|/bin/bash|/bin/sh)|\|\s*(ls|cat|id|whoami)|`\w+`|\$\(|system\(|exec\(|shell_exec\(|passthru\()",
        "stage_code": "suspicious_action",
        "description": "检测命令注入和代码执行特征",
    },
    {
        "rule_code": "ACC_BRUTE_001",
        "rule_name": "暴力破解检测",
        "category": "account",
        "attack_type": "Brute Force",
        "severity": "high",
        "rule_pattern": "",  # 基于统计而非正则
        "rule_config": {
            "match_type": "statistical",
            "field": "src_ip",
            "condition": "login_fail_count >= threshold",
            "threshold_ref": "brute_force_threshold",
            "time_window_minutes": 10,
        },
        "stage_code": "abnormal_login",
        "description": "检测同 IP 短时间内多次登录失败行为",
    },
    {
        "rule_code": "WEB_SCAN_001",
        "rule_name": "高频扫描检测",
        "category": "web",
        "attack_type": "Scanning",
        "severity": "medium",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "src_ip",
            "condition": "request_count >= threshold",
            "threshold_ref": "high_freq_threshold",
            "time_window_seconds": 60,
        },
        "stage_code": "recon",
        "description": "检测短时间内高频访问行为，识别扫描探测",
    },
    {
        "rule_code": "WEB_SENS_001",
        "rule_name": "敏感路径检测",
        "category": "web",
        "attack_type": "Sensitive Path Access",
        "severity": "medium",
        "rule_pattern": r"(?i)(/admin|/\.git|/\.env|/backup|/config|/wp-admin|/phpmyadmin|/console|/\.svn|/\.htaccess|/server-status|/actuator)",
        "stage_code": "sensitive_path",
        "description": "检测对敏感路径的访问尝试",
    },
    {
        "rule_code": "WEB_UA_001",
        "rule_name": "异常 User-Agent 检测",
        "category": "web",
        "attack_type": "Abnormal UA",
        "severity": "low",
        "rule_pattern": r"(?i)(curl|wget|python-requests|Go-http-client|nikto|nmap|sqlmap|acunetix|nessus|openvas)",
        "stage_code": "recon",
        "description": "检测自动化工具或扫描器的 User-Agent 特征",
    },
    {
        "rule_code": "ACC_ABNORMAL_001",
        "rule_name": "异常登录时间段检测",
        "category": "account",
        "attack_type": "Abnormal Login",
        "severity": "medium",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "event_time",
            "condition": "hour between 0 and 6",
            "threshold_ref": "",
            "time_window_minutes": 0,
        },
        "stage_code": "abnormal_login",
        "description": "检测非工作时段（0:00-6:00）的登录行为",
    },
    # ── 进阶检测规则 ──
    {
        "rule_code": "WEB_WEBSHELL_001",
        "rule_name": "Webshell 访问检测",
        "category": "web",
        "attack_type": "Webshell Access",
        "severity": "critical",
        "rule_pattern": r"(?i)(\.jsp\b.*\?.*(cmd|exec|shell|pass)|\.asp\b.*\?.*(cmd|exec|shell)|\.php\b.*\?.*(cmd|exec|shell|eval|system)|/webshell|/shell\.|cmd\.php|eval\.php)",
        "stage_code": "suspicious_action",
        "description": "检测可疑 Webshell 文件访问、命令执行参数特征",
    },
    {
        "rule_code": "WEB_SSRF_001",
        "rule_name": "SSRF 尝试检测",
        "category": "web",
        "attack_type": "SSRF",
        "severity": "high",
        "rule_pattern": r"(?i)(url=https?://[0-9]{1,3}\.[0-9]{1,3}\.|url=file://|url=dict://|url=gopher://|endpoint=http://(localhost|127\.0\.0\.1|10\.|172\.|192\.168)|callback=http://(localhost|127|10\.))\S*",
        "stage_code": "exploit_attempt",
        "description": "检测 SSRF 攻击特征，包括内网地址探测、file/dict/gopher 协议尝试",
    },
    {
        "rule_code": "WEB_FILEUPLOAD_001",
        "rule_name": "异常文件上传检测",
        "category": "web",
        "attack_type": "Malicious File Upload",
        "severity": "high",
        "rule_pattern": r"(?i)(\.(php|jsp|asp|exe|sh|pl|py|cgi)\s*$|filename=.*\.(php|jsp|asp|exe|sh)\b|Content-Disposition.*\.(php5|phtml|asp\.|jsp\b))",
        "stage_code": "exploit_attempt",
        "description": "检测可疑文件上传，如 PHP、JSP、ASP 脚本文件上传",
    },
    {
        "rule_code": "WEB_LFI_001",
        "rule_name": "本地文件包含检测",
        "category": "web",
        "attack_type": "File Inclusion",
        "severity": "high",
        "rule_pattern": r"(?i)(file=|include=|require=|page=|document=|root=|folder=|path=)(/etc|/var|/proc|/home|/root|/tmp|c:\\|\.\./|\.\.\\)",
        "stage_code": "suspicious_action",
        "description": "检测本地文件包含（LFI）攻击，如读取 /etc/passwd 等系统文件",
    },
    {
        "rule_code": "NET_PORTSCAN_001",
        "rule_name": "端口扫描行为检测",
        "category": "network",
        "attack_type": "Port Scan",
        "severity": "medium",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "src_ip",
            "condition": "unique_ports >= threshold",
            "threshold_ref": "port_scan_threshold",
            "time_window_seconds": 30,
        },
        "stage_code": "recon",
        "description": "检测同 IP 短时间内访问多个端口的行为",
    },
    # ── 主机安全检测规则 ──
    {
        "rule_code": "HOST_SSH_BRUTE_001",
        "rule_name": "SSH 暴力破解检测",
        "category": "host",
        "attack_type": "SSH Brute Force",
        "severity": "high",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "src_ip",
            "condition": "ssh_fail_count >= threshold",
            "threshold_ref": "brute_force_threshold",
            "time_window_minutes": 10,
            "log_type_filter": "host",
        },
        "stage_code": "credential_access",
        "description": "检测同 IP 短时间内多次 SSH 登录失败行为",
    },
    {
        "rule_code": "HOST_SSH_SUCCESS_001",
        "rule_name": "SSH 爆破成功检测",
        "category": "host",
        "attack_type": "SSH Brute Force Success",
        "severity": "critical",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "src_ip",
            "condition": "ssh_fail_before_success",
            "threshold_ref": "brute_force_threshold",
            "time_window_minutes": 15,
            "log_type_filter": "host",
        },
        "stage_code": "initial_access",
        "description": "检测同 IP 在短时间内 SSH 失败后成功登录的行为",
    },
    {
        "rule_code": "HOST_SUDO_SENSITIVE_001",
        "rule_name": "敏感 sudo 命令执行检测",
        "category": "host",
        "attack_type": "Suspicious Sudo",
        "severity": "high",
        "rule_pattern": r"(?i)(/bin/sh|/bin/bash|/bin/dash|python|perl|ruby|cat\s+/etc/shadow|cat\s+/etc/passwd|cat\s+/etc/sudoers|useradd|adduser|chmod\s+777|passwd\s+\w+|visudo|wget\s|curl\s|/dev/tcp|/dev/udp)",
        "stage_code": "privilege_escalation",
        "description": "检测通过 sudo 执行敏感命令，如添加用户、修改密码、反弹 Shell",
    },
    {
        "rule_code": "HOST_ABNORMAL_TIME_001",
        "rule_name": "异常时间段 SSH 登录检测",
        "category": "host",
        "attack_type": "Abnormal SSH Login Time",
        "severity": "medium",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "event_time",
            "condition": "hour between 0 and 6",
            "threshold_ref": "",
            "time_window_minutes": 0,
            "log_type_filter": "host",
        },
        "stage_code": "initial_access",
        "description": "检测非工作时段（0:00-6:00）的 SSH 登录行为",
    },
    # ── 网络安全检测规则 ──
    {
        "rule_code": "NET_SURICATA_SCAN_001",
        "rule_name": "Suricata 端口扫描检测",
        "category": "network",
        "attack_type": "Network Scan",
        "severity": "medium",
        "rule_pattern": r"(?i)(SCAN|scan|portscan|Port Scan|SSH Scan)",
        "stage_code": "recon",
        "description": "检测 Suricata 识别的端口扫描和探测行为",
    },
    {
        "rule_code": "NET_SURICATA_ATTACK_001",
        "rule_name": "Suricata Web 攻击检测",
        "category": "network",
        "attack_type": "Network Web Attack",
        "severity": "high",
        "rule_pattern": r"(?i)(Web Application Attack|SQL Injection|XSS|Command Injection)",
        "stage_code": "exploit_attempt",
        "description": "检测 Suricata 识别的 Web 应用攻击事件",
    },
    {
        "rule_code": "NET_DNS_C2_001",
        "rule_name": "可疑 DNS 查询检测",
        "category": "network",
        "attack_type": "DNS Suspicious Query",
        "severity": "high",
        "rule_pattern": r"(?i)(\.malware\.|\.c2\.|\.evil\.|\.botnet\.|\.ransomware\.|\.phishing\.)",
        "stage_code": "suspicious_action",
        "description": "检测可疑 DNS 查询，识别 C2 通信和恶意域名",
    },
    {
        "rule_code": "NET_ZEEK_CONN_001",
        "rule_name": "Zeek 异常连接检测",
        "category": "network",
        "attack_type": "Abnormal Connection",
        "severity": "low",
        "rule_pattern": "",
        "rule_config": {
            "match_type": "statistical",
            "field": "src_ip",
            "condition": "unique_dst_ports >= threshold",
            "threshold_ref": "port_scan_threshold",
            "time_window_seconds": 30,
            "log_type_filter": "network",
        },
        "stage_code": "recon",
        "description": "检测同源 IP 短时间内访问多个目标端口的行为",
    },
]


def seed_rules():
    app = create_app("development")
    with app.app_context():
        count = 0
        for rule_data in RULES:
            existing = DetectionRule.query.filter_by(rule_code=rule_data["rule_code"]).first()
            if not existing:
                db.session.add(DetectionRule(**rule_data))
                count += 1
        db.session.commit()
        print(f"[OK 已添加 {count} 条检测规则")


if __name__ == "__main__":
    seed_rules()
   