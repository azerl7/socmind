"""规则引擎服务：对日志执行规则检测并生成告警

支持两种检测模式：
  1. regex_match   — 正则匹配 URL/参数/UA 等字段
  2. statistical   — 基于统计的检测（暴力破解、高频访问等）
"""
import re
import json
from datetime import datetime, timedelta, timezone
from typing import List
from collections import defaultdict

from app import db
from app.models.log import RawLog
from app.models.rule import DetectionRule
from app.models.alert import Alert, AlertEvidence
from app.models.config import SystemConfig
from app.utils.security import generate_alert_no, generate_event_no


# ── 预编译规则缓存 ──
_rule_cache: dict | None = None
_rule_cache_time: datetime | None = None
CACHE_TTL_SECONDS = 60


def _get_config(key: str, default=None) -> str:
    """从系统配置表取值"""
    config = SystemConfig.query.filter_by(config_key=key).first()
    if config and config.config_value:
        return config.config_value
    return default


def load_rules(category: str | None = None) -> List[DetectionRule]:
    """加载启用的规则（带缓存）"""
    global _rule_cache, _rule_cache_time
    now = datetime.now(timezone.utc)

    if _rule_cache is None or (
        _rule_cache_time and (now - _rule_cache_time).total_seconds() > CACHE_TTL_SECONDS
    ):
        _rule_cache = {
            r.id: r for r in DetectionRule.query.filter_by(enabled=1).all()
        }
        _rule_cache_time = now

    if category:
        return [r for r in _rule_cache.values() if r.category == category]
    return list(_rule_cache.values())


def invalidate_rule_cache():
    """使规则缓存失效（规则变更时调用）"""
    global _rule_cache, _rule_cache_time
    _rule_cache = None
    _rule_cache_time = None


# ── 正则检测 ──

def _match_regex(rule: DetectionRule, log: RawLog) -> dict | None:
    """对单条日志执行正则检测，返回命中的证据信息或 None"""
    if not rule.rule_pattern:
        return None

    try:
        pattern = re.compile(rule.rule_pattern)
    except re.error:
        return None

    # 检测字段：URL、请求参数、UA、原始内容
    check_fields = {
        "url": log.url or "",
        "user_agent": log.user_agent or "",
        "raw_content": log.raw_content or "",
    }

    for field_name, field_value in check_fields.items():
        m = pattern.search(field_value)
        if m:
            return {
                "matched_field": field_name,
                "matched_content": m.group()[:200],
                "evidence_title": f"规则 {rule.rule_code} 命中 {field_name}",
                "evidence_content": f"匹配特征: {m.group()[:200]}",
            }
    return None


# ── 统计检测 ──

def _statistical_check(rule: DetectionRule, log_type: str) -> List[dict]:
    """基于统计的检测（暴力破解、高频扫描等）

    返回 list[ {log_id, src_ip, evidence_info} ]
    """
    config = rule.rule_config or {}
    field = config.get("field", "")
    condition = config.get("condition", "")
    threshold_ref = config.get("threshold_ref", "")
    window_minutes = config.get("time_window_minutes", 10)
    window_seconds = config.get("time_window_seconds", 60)

    if not condition:
        return []

    # 获取阈值
    threshold = int(_get_config(threshold_ref, "5")) if threshold_ref else 5

    now = datetime.now(timezone.utc)
    results = []

    if rule.rule_code == "ACC_BRUTE_001":
        # 暴力破解：同 IP 短时间内多次登录失败
        window_start = now - timedelta(minutes=window_minutes)
        fail_logs = RawLog.query.filter(
            RawLog.log_type == "login",
            RawLog.result == "fail",
            RawLog.event_time >= window_start,
        ).all()

        ip_counts = defaultdict(list)
        for log in fail_logs:
            ip_counts[log.src_ip].append(log)

        for ip, logs in ip_counts.items():
            if len(logs) >= threshold:
                # 检查是否已有暴力破解告警（防重复）
                existing = Alert.query.filter(
                    Alert.attack_type == "Brute Force",
                    Alert.src_ip == ip,
                    Alert.event_time >= window_start,
                ).first()
                if existing:
                    continue

                for log in logs[:1]:  # 每个 IP 只生成一条
                    results.append({
                        "log_id": log.id,
                        "src_ip": ip,
                        "evidence_title": f"暴力破解检测: {ip}",
                        "evidence_content": f"在 {window_minutes} 分钟内失败 {len(logs)} 次，阈值 {threshold}",
                        "log": log,
                    })
                break

    elif rule.rule_code == "WEB_SCAN_001":
        # 高频扫描：同 IP 单位时间内访问次数
        window_start = now - timedelta(seconds=window_seconds)
        recent_logs = RawLog.query.filter(
            RawLog.log_type == "web",
            RawLog.event_time >= window_start,
        ).all()

        ip_counts = defaultdict(list)
        for log in recent_logs:
            ip_counts[log.src_ip].append(log)

        for ip, logs in ip_counts.items():
            if len(logs) >= threshold:
                existing = Alert.query.filter(
                    Alert.attack_type == "Scanning",
                    Alert.src_ip == ip,
                    Alert.event_time >= window_start,
                ).first()
                if existing:
                    continue
                results.append({
                    "log_id": logs[0].id,
                    "src_ip": ip,
                    "evidence_title": f"高频扫描检测: {ip}",
                    "evidence_content": f"在 {window_seconds} 秒内请求 {len(logs)} 次，阈值 {threshold}",
                    "log": logs[0],
                })

    elif rule.rule_code == "ACC_ABNORMAL_001":
        # 异常时间段登录（0:00-6:00）
        abnormal_logs = RawLog.query.filter(
            RawLog.log_type == "login",
            RawLog.event_time >= (now - timedelta(hours=24)),
        ).all()

        seen_ips = set()
        for log in abnormal_logs:
            if log.event_time and log.event_time.hour < 6 and log.src_ip and log.src_ip not in seen_ips:
                seen_ips.add(log.src_ip)
                results.append({
                    "log_id": log.id,
                    "src_ip": log.src_ip,
                    "evidence_title": f"异常时段登录: {log.src_ip}",
                    "evidence_content": f"在 {log.event_time.strftime('%H:%M')} 登录",
                    "log": log,
                })

    elif rule.rule_code == "NET_PORTSCAN_001":
        # 端口扫描：同 IP 短时间内访问多个不同端口
        window_start = now - timedelta(seconds=window_seconds)
        recent_logs = RawLog.query.filter(
            RawLog.event_time >= window_start,
            RawLog.src_port.isnot(None),
        ).all()

        ip_ports = defaultdict(set)
        ip_logs = defaultdict(list)
        for log in recent_logs:
            if log.src_port:
                ip_ports[log.src_ip].add(log.src_port)
                ip_logs[log.src_ip].append(log)

        for ip, ports in ip_ports.items():
            if len(ports) >= threshold:
                existing = Alert.query.filter(
                    Alert.attack_type == "Port Scan",
                    Alert.src_ip == ip,
                    Alert.event_time >= window_start,
                ).first()
                if existing:
                    continue
                results.append({
                    "log_id": ip_logs[ip][0].id if ip_logs[ip] else None,
                    "src_ip": ip,
                    "evidence_title": f"端口扫描检测: {ip}",
                    "evidence_content": f"在 {window_seconds} 秒内访问 {len(ports)} 个不同端口，阈值 {threshold}",
                    "log": ip_logs[ip][0] if ip_logs[ip] else None,
                })

    # ── 主机安全检测 ──
    elif rule.rule_code == "HOST_SSH_BRUTE_001":
        # SSH 暴力破解：同 IP 短时间内多次 SSH 登录失败
        window_start = now - timedelta(minutes=window_minutes)
        fail_logs = RawLog.query.filter(
            RawLog.log_type == "host",
            RawLog.result == "fail",
            RawLog.action == "ssh_login",
            RawLog.event_time >= window_start,
        ).all()

        ip_counts = defaultdict(list)
        for log in fail_logs:
            ip_counts[log.src_ip].append(log)

        for ip, logs in ip_counts.items():
            if len(logs) >= threshold:
                existing = Alert.query.filter(
                    Alert.attack_type == "SSH Brute Force",
                    Alert.src_ip == ip,
                    Alert.event_time >= window_start,
                ).first()
                if existing:
                    continue
                for log in logs[:1]:
                    results.append({
                        "log_id": log.id,
                        "src_ip": ip,
                        "evidence_title": f"SSH 暴力破解检测: {ip}",
                        "evidence_content": f"在 {window_minutes} 分钟内 SSH 登录失败 {len(logs)} 次，阈值 {threshold}",
                        "log": log,
                    })
                break

    elif rule.rule_code == "HOST_SSH_SUCCESS_001":
        # SSH 爆破成功：同 IP 的 SSH 失败后成功登录
        window_start = now - timedelta(minutes=window_minutes)
        host_logs = RawLog.query.filter(
            RawLog.log_type == "host",
            RawLog.event_time >= window_start,
        ).order_by(RawLog.event_time).all()

        # 按 IP 分组，检查是否有先失败后成功的模式
        ip_events = defaultdict(list)
        for log in host_logs:
            if log.src_ip:
                ip_events[log.src_ip].append(log)

        for ip, logs in ip_events.items():
            has_fail = False
            has_success = False
            for log in logs:
                if log.action == "ssh_login" and log.result == "fail":
                    has_fail = True
                if log.action == "ssh_login" and log.result == "success" and has_fail:
                    has_success = True
                    break
            if has_fail and has_success:
                existing = Alert.query.filter(
                    Alert.attack_type == "SSH Brute Force Success",
                    Alert.src_ip == ip,
                    Alert.event_time >= window_start,
                ).first()
                if existing:
                    continue
                results.append({
                    "log_id": logs[-1].id,
                    "src_ip": ip,
                    "evidence_title": f"SSH 爆破成功检测: {ip}",
                    "evidence_content": f"在 {window_minutes} 分钟内从 {ip} 的 SSH 登录在失败后成功",
                    "log": logs[-1],
                })

    elif rule.rule_code == "HOST_ABNORMAL_TIME_001":
        # 异常时间段 SSH 登录（0:00-6:00）
        abnormal_logs = RawLog.query.filter(
            RawLog.log_type == "host",
            RawLog.action == "ssh_login",
            RawLog.event_time >= (now - timedelta(hours=24)),
        ).all()

        seen_ips = set()
        for log in abnormal_logs:
            if log.event_time and log.event_time.hour < 6 and log.src_ip and log.src_ip not in seen_ips:
                seen_ips.add(log.src_ip)
                results.append({
                    "log_id": log.id,
                    "src_ip": log.src_ip,
                    "evidence_title": f"异常时段 SSH 登录: {log.src_ip}",
                    "evidence_content": f"在 {log.event_time.strftime('%H:%M')} 通过 SSH 登录",
                    "log": log,
                })

    return results


# ── 检测执行 ──

def run_detection(
    log_type: str | None = None,
    rule_ids: List[int] | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict:
    """执行规则检测，生成告警

    Args:
        log_type: 限定日志类型
        rule_ids: 限定规则 ID 列表
        start_time: 日志时间范围起始
        end_time: 日志时间范围结束

    Returns:
        {"checked_count": int, "alert_count": int}
    """
    rules = load_rules(log_type)
    if rule_ids:
        rules = [r for r in rules if r.id in rule_ids]

    if not rules:
        return {"checked_count": 0, "alert_count": 0}

    # 查询待检测日志
    query = RawLog.query
    if log_type:
        query = query.filter(RawLog.log_type == log_type)
    if start_time:
        query = query.filter(RawLog.event_time >= start_time)
    if end_time:
        query = query.filter(RawLog.event_time <= end_time)

    logs = query.order_by(RawLog.event_time).all()
    checked_count = len(logs)
    alert_count = 0

    # 正则规则 → 逐条检测
    regex_rules = [r for r in rules if r.rule_pattern and r.rule_config is None or r.rule_config.get("match_type") != "statistical"]
    stat_rules = [r for r in rules if r.rule_config and r.rule_config.get("match_type") == "statistical"]

    # 加载抑制规则
    from app.services.suppression_service import check_suppression

    for log in logs:
        for rule in regex_rules:
            result = _match_regex(rule, log)
            if result:
                # 检查是否被抑制
                alert_data = {
                    "src_ip": log.src_ip or "",
                    "attack_type": rule.attack_type,
                    "severity": rule.severity,
                    "rule_code": rule.rule_code,
                    "dst_ip": log.dst_ip or "",
                }
                supp = check_suppression(alert_data)
                if supp:
                    continue  # 跳过被抑制的告警
                _create_alert(rule, log, result)
                alert_count += 1

    # 统计规则 → 批量检测
    for rule in stat_rules:
        results = _statistical_check(rule, log_type or "")
        for res in results:
            log_obj = res.get("log")
            if log_obj:
                _create_alert(rule, log_obj, res)
                alert_count += 1

    return {"checked_count": checked_count, "alert_count": alert_count}


def _create_alert(rule: DetectionRule, log: RawLog, match_info: dict):
    """根据规则命中结果创建告警"""
    # 风险分：根据严重等级
    severity_scores = {"low": 20, "medium": 50, "high": 75, "critical": 95}
    base_score = severity_scores.get(rule.severity, 50)

    alert = Alert(
        alert_no=generate_alert_no(),
        title=f"检测到{rule.attack_type}",
        rule_id=rule.id,
        raw_log_id=log.id,
        attack_type=rule.attack_type,
        severity=rule.severity,
        risk_score=base_score,
        src_ip=log.src_ip,
        dst_ip=log.dst_ip,
        username=log.username,
        event_time=log.event_time or datetime.now(timezone.utc),
        status="new",
    )
    db.session.add(alert)
    db.session.flush()  # 获取 alert.id

    # 创建证据
    evidence = AlertEvidence(
        alert_id=alert.id,
        evidence_type="rule",
        title=match_info.get("evidence_title", f"命中规则: {rule.rule_code}"),
        content=match_info.get("evidence_content", ""),
    )
    db.session.add(evidence)

    # 添加原始日志证据
    log_evidence = AlertEvidence(
        alert_id=alert.id,
        evidence_type="log",
        title="原始日志",
        content=log.raw_content[:2000],
    )
    db.session.add(log_evidence)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
