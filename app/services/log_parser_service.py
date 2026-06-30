"""日志解析服务：支持 Web 访问日志、登录日志、WAF JSON 日志解析为统一格式"""
import csv
import json
import io
import re
from datetime import datetime
from time import timezone
from typing import Generator

from app import db
from app.models.log import RawLog, LogImportTask


# 不同类型日志对应的目标 IP(模拟「被攻击的资源」)
# nginx / host / login 日志格式本身不带目标 IP 字段,只能由解析器侧硬编码
# waf / network 原始日志里已经包含 dst_ip,不在这里处理
LOG_TARGET_IPS = {
    "web": "10.0.0.50",     # Web 服务器 IP(被攻击资源)
    "host": "10.0.0.20",    # SSH 主机 IP(被尝试登录的服务器)
    "login": "10.0.0.20",   # 业务登录主机 IP
}


# ── SSH auth.log 格式 ──
# SSH auth 正则: 提取时间、用户、IP、操作类型
SSH_AUTH_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+\.?\[\d+\]:\s+'
    r'(?P<action>Failed password|Accepted password|Invalid user)\s+(?:for\s+)?'
    r'(?P<username>\S+)?\s+'
    r'(?:from\s+)?(?P<src_ip>\S+)?'
)

# Sudo 命令日志
SUDO_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo\[\d+\]:\s+'
    r'(?P<username>\S+)\s+:\s+.*COMMAND=(?P<command>.+)'
)


def parse_auth_log(line: str) -> dict | None:
    """解析单行 SSH / sudo auth.log 日志"""
    m = SSH_AUTH_PATTERN.match(line.strip())
    if m:
        g = m.groupdict()
        action = g.get("action", "")
        result = ""
        username = g.get("username") or ""
        src_ip = g.get("src_ip") or ""

        if "Failed" in action or "Invalid" in action:
            result = "fail"
        elif "Accepted" in action:
            result = "success"
        else:
            result = "unknown"

        event_time = None
        try:
            event_time = datetime.strptime(g["timestamp"], "%b %d %H:%M:%S")
            event_time = event_time.replace(year=datetime.now().year)
        except (ValueError, TypeError):
            pass

        return {
            "log_type": "host",
            "src_ip": src_ip,
            "dst_ip": LOG_TARGET_IPS["host"],
            "username": username,
            "action": "ssh_login",
            "result": result,
            "event_time": event_time,
            "raw_content": line.strip(),
        }

    m = SUDO_PATTERN.match(line.strip())
    if m:
        g = m.groupdict()
        event_time = None
        try:
            event_time = datetime.strptime(g["timestamp"], "%b %d %H:%M:%S")
            event_time = event_time.replace(year=datetime.now().year)
        except (ValueError, TypeError):
            pass

        return {
            "log_type": "host",
            "src_ip": "",
            "dst_ip": LOG_TARGET_IPS["host"],
            "username": g.get("username", ""),
            "action": "sudo",
            "result": "success" if g.get("command") else "unknown",
            "url": g.get("command", ""),
            "event_time": event_time,
            "raw_content": line.strip(),
        }

    return None


# ── Nginx 日志格式 ──
# 标准 combined 格式: IP - - [time] "method url proto" status size "referer" "ua"
NGINX_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_nginx_log(line: str) -> dict | None:
    """解析单行 Nginx 日志"""
    m = NGINX_PATTERN.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    # 解析时间: 07/May/2026:10:12:00 +0000
    event_time = None
    try:
        event_time = datetime.strptime(g["time"], "%d/%b/%Y:%H:%M:%S %z")
    except (ValueError, TypeError):
        pass

    return {
        "log_type": "web",
        "src_ip": g["ip"],
        "dst_ip": LOG_TARGET_IPS["web"],
        "http_method": g["method"],
        "url": g["url"],
        "status_code": int(g["status"]) if g["status"].isdigit() else None,
        "user_agent": g.get("ua", ""),
        "event_time": event_time,
        "raw_content": line.strip(),
    }


# ── Suricata eve.json 解析 ──

def _parse_suricata_entry(entry: dict, source: str = "") -> dict | None:
    """解析单条 Suricata eve.json 告警/网络事件"""
    event_time = None
    ts = entry.get("timestamp", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            event_time = datetime.strptime(ts, fmt)
            break
        except (ValueError, TypeError):
            continue

    src_ip = entry.get("src_ip", "")
    dst_ip = entry.get("dest_ip", "")
    src_port = entry.get("src_port")
    dst_port = entry.get("dest_port")
    proto = entry.get("proto", "")
    event_type = entry.get("event_type", "")

    url = ""
    http_method = ""
    ua = ""
    if "http" in entry and entry["http"]:
        url = entry["http"].get("url", "")
        http_method = entry["http"].get("http_method", "")
        ua = entry["http"].get("http_user_agent", "")

    # 提取告警信息
    alert_info = {}
    action = ""
    severity = "medium"
    if "alert" in entry and entry["alert"]:
        alert_info = {
            "signature_id": entry["alert"].get("signature_id"),
            "signature": entry["alert"].get("signature", ""),
            "category": entry["alert"].get("category", ""),
            "severity": entry["alert"].get("severity", 2),
        }
        action = entry["alert"].get("action", "alert")
        sev_map = {1: "critical", 2: "high", 3: "medium", 4: "low"}
        severity = sev_map.get(entry["alert"].get("severity", 2), "medium")

    # 提取 DNS 查询
    dns_query = ""
    if "dns" in entry and entry["dns"]:
        dns_query = entry["dns"].get("rrtname", "") or entry["dns"].get("query", "")

    return {
        "log_type": "network",
        "source": source or "suricata",
        "event_time": event_time,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "http_method": http_method,
        "url": url,
        "user_agent": ua,
        "action": action,
        "result": event_type,
        "parsed_json": {
            "event_type": event_type,
            "proto": proto,
            "alert": alert_info,
            "dns_query": dns_query,
        },
        "raw_content": json.dumps(entry, ensure_ascii=False),
    }


# ── Zeek conn.log 解析 ──

ZEEK_FIELD_NAMES = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]


def _parse_zeek_conn_line(line: str, source: str = "") -> dict | None:
    """解析单行 Zeek conn.log"""
    parts = line.split("\t")
    if len(parts) < 6:
        return None

    event_time = None
    try:
        ts = float(parts[0])
        event_time = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, TypeError):
        pass

    fields = {}
    for i, name in enumerate(ZEEK_FIELD_NAMES):
        if i < len(parts):
            fields[name] = parts[i]

    return {
        "log_type": "network",
        "source": source or "zeek",
        "event_time": event_time,
        "src_ip": fields.get("id.orig_h", ""),
        "src_port": int(fields["id.orig_p"]) if fields.get("id.orig_p", "").isdigit() else None,
        "dst_ip": fields.get("id.resp_h", ""),
        "dst_port": int(fields["id.resp_p"]) if fields.get("id.resp_p", "").isdigit() else None,
        "action": fields.get("conn_state", ""),
        "result": fields.get("service", ""),
        "parsed_json": {
            "proto": fields.get("proto", ""),
            "duration": fields.get("duration"),
            "orig_bytes": fields.get("orig_bytes"),
            "resp_bytes": fields.get("resp_bytes"),
        },
        "raw_content": line.strip(),
    }


def parse_login_csv_row(row: dict) -> dict | None:
    """解析单行登录日志 CSV"""
    event_time = None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            event_time = datetime.strptime(row.get("time", ""), fmt)
            break
        except (ValueError, TypeError):
            continue

    result = row.get("result", "").lower()
    return {
        "log_type": "login",
        "src_ip": row.get("src_ip", ""),
        "dst_ip": LOG_TARGET_IPS["login"],
        "username": row.get("username", ""),
        "action": row.get("action", "login"),
        "result": "success" if result in ("success", "true", "1", "ok") else "fail",
        "event_time": event_time,
        "raw_content": json.dumps(row, ensure_ascii=False),
    }


def parse_waf_json_entry(entry: dict) -> dict | None:
    """解析单条 WAF JSON 告警"""
    event_time = None
    ts = entry.get("timestamp", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S+00:00",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            event_time = datetime.strptime(ts, fmt)
            # 处理 +00:00 时区偏移
            if ts.endswith("+00:00") and "T" in ts:
                event_time = datetime.strptime(ts.replace("+00:00", ""), "%Y-%m-%dT%H:%M:%S")
            break
        except (ValueError, TypeError):
            continue

    return {
        "log_type": "waf",
        "src_ip": entry.get("src_ip", ""),
        "dst_ip": entry.get("dst_ip", ""),
        "url": entry.get("url", ""),
        "http_method": entry.get("request_method", "GET"),
        "user_agent": entry.get("user_agent", ""),
        "action": entry.get("action", "alert"),
        "result": entry.get("action", "alert"),
        "event_time": event_time,
        "parsed_json": {
            "rule_id": entry.get("rule_id", ""),
            "attack_type": entry.get("attack_type", ""),
            "severity": entry.get("severity", "medium"),
        },
        "raw_content": json.dumps(entry, ensure_ascii=False),
    }


def parse_log_content(
    content: str,
    log_type: str,
    source: str = "",
) -> Generator[dict, None, None]:
    """根据日志类型解析文件内容，逐条 yield 标准化日志字典"""
    lines = content.splitlines()

    if log_type == "web":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parsed = parse_nginx_log(line)
            if parsed:
                parsed["source"] = source or "nginx"
                yield parsed

    elif log_type == "login":
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            parsed = parse_login_csv_row(row)
            if parsed:
                parsed["source"] = source or "login_log"
                yield parsed

    elif log_type == "waf":
        try:
            entries = json.loads(content)
        except json.JSONDecodeError:
            # 可能每行一条 JSON
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    parsed = parse_waf_json_entry(entry)
                    if parsed:
                        parsed["source"] = source or "waf"
                        yield parsed
                except json.JSONDecodeError:
                    continue
            return

        if isinstance(entries, list):
            for entry in entries:
                parsed = parse_waf_json_entry(entry)
                if parsed:
                    parsed["source"] = source or "waf"
                    yield parsed

    elif log_type == "host":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parsed = parse_auth_log(line)
            if parsed:
                parsed["source"] = source or "auth_log"
                yield parsed
            else:
                # 无法解析的行也作为原始内容保留
                yield {
                    "log_type": "host",
                    "source": source or "host",
                    "raw_content": line,
                    "event_time": None,
                }

    elif log_type == "network":
        # Suricata eve.json 格式
        try:
            entries = json.loads(content)
            if isinstance(entries, list):
                for entry in entries:
                    parsed = _parse_suricata_entry(entry, source)
                    if parsed:
                        yield parsed
                    return
        except (json.JSONDecodeError, ValueError):
            pass

        # Zeek conn.log 格式（tab分隔）
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = _parse_zeek_conn_line(line, source)
            if parsed:
                yield parsed
            else:
                yield {
                    "log_type": "network",
                    "source": source or "network",
                    "raw_content": line,
                    "event_time": None,
                }


def process_import_task(task_id: int) -> dict:
    """执行导入任务：读取文件、解析、入库"""
    task = db.session.get(LogImportTask, task_id)
    if not task:
        raise ValueError(f"导入任务不存在: {task_id}")

    task.status = "running"
    db.session.commit()

    try:
        with open(task.file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        task.status = "failed"
        task.error_message = f"文件不存在: {task.file_path}"
        db.session.commit()
        return {"task_id": task_id, "total": 0, "success": 0, "failed": 0}

    success_count = 0
    failed_count = 0
    batch = []
    batch_size = 200

    for parsed in parse_log_content(content, task.log_type, task.filename):
        try:
            log = RawLog(
                import_task_id=task.id,
                log_type=parsed.get("log_type", task.log_type),
                source=parsed.get("source", ""),
                event_time=parsed.get("event_time"),
                src_ip=parsed.get("src_ip"),
                src_port=parsed.get("src_port"),
                dst_ip=parsed.get("dst_ip"),
                dst_port=parsed.get("dst_port"),
                username=parsed.get("username"),
                http_method=parsed.get("http_method"),
                url=parsed.get("url"),
                status_code=parsed.get("status_code"),
                user_agent=parsed.get("user_agent"),
                action=parsed.get("action"),
                result=parsed.get("result"),
                raw_content=parsed.get("raw_content", ""),
                parsed_json=parsed.get("parsed_json"),
            )
            batch.append(log)
            success_count += 1
            if len(batch) >= batch_size:
                db.session.bulk_save_objects(batch)
                batch.clear()
        except Exception:
            failed_count += 1
    if batch:
        db.session.bulk_save_objects(batch)
    task.status = "success"
    task.total_count = success_count + failed_count
    task.success_count = success_count
    task.failed_count = failed_count
    db.session.commit()
    return {"task_id": task_id, "total": success_count + failed_count,
            "success": success_count, "failed": failed_count}


def deduplicate_logs(log_type: str | None = None, hours: int = 24) -> int:
    """L-10: 日志去重 — 基于 raw_content 和事件时间窗口删除重复日志

    检测规则: 相同 raw_content、相同 log_type、相同 src_ip、
             在指定时间窗口内的事件被视为重复
    Args:
        log_type: 限定日志类型（None=全部）
        hours: 去重时间窗口（小时）
    Returns:
        删除的重复记录数
    """
    from datetime import timedelta
    from sqlalchemy import func

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=hours)

    query = RawLog.query.filter(RawLog.event_time >= window_start)
    if log_type:
        query = query.filter(RawLog.log_type == log_type)

    logs = query.order_by(RawLog.event_time).all()

    # 分组: (raw_content_hash, log_type, src_ip) → 保留第一条
    seen = {}
    to_delete = []

    for log in logs:
        # 对 raw_content 取前 500 字符作 hash（避免超长内容）
        content_key = hash(log.raw_content[:500] if log.raw_content else "")
        key = (content_key, log.log_type, log.src_ip or "")

        if key in seen:
            # 时间相近（5分钟内）→ 重复
            first_time = seen[key]
            if first_time and log.event_time:
                diff = abs((log.event_time - first_time).total_seconds())
                if diff < 300:  # 5分钟
                    to_delete.append(log.id)
                    continue
        else:
            seen[key] = log.event_time

    if not to_delete:
        return 0

    # 只删除没有任何关联告警的重复日志
    from app.models.alert import Alert
    deleted = 0
    for log_id in to_delete:
        existing_alert = Alert.query.filter_by(raw_log_id=log_id).first()
        if not existing_alert:
            RawLog.query.filter_by(id=log_id).delete()
            deleted += 1

    db.session.commit()
    return deleted
