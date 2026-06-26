"""告警管理服务：告警查询、状态流转、聚合、去重"""
from datetime import datetime, timezone
from typing import List
from collections import defaultdict

from app import db
from app.models.alert import Alert, AlertEvent, EventAlertRelation
from app.models.config import SystemConfig
from app.utils.security import generate_event_no


def _get_time_window_minutes() -> int:
    config = SystemConfig.query.filter_by(config_key="alert_time_window_minutes").first()
    if config and config.config_value:
        try:
            return int(config.config_value)
        except ValueError:
            pass
    return 10


# ── 告警查询 ──

def query_alerts(
    page: int = 1,
    page_size: int = 20,
    severity: str | None = None,
    status: str | None = None,
    attack_type: str | None = None,
    src_ip: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict:
    """分页查询告警列表"""
    q = Alert.query

    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    if attack_type:
        q = q.filter(Alert.attack_type == attack_type)
    if src_ip:
        q = q.filter(Alert.src_ip == src_ip)
    if start_time:
        q = q.filter(Alert.event_time >= start_time)
    if end_time:
        q = q.filter(Alert.event_time <= end_time)

    pagination = q.order_by(Alert.event_time.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return {
        "items": [a.to_dict() for a in pagination.items],
        "page": page,
        "page_size": page_size,
        "total": pagination.total,
    }


def get_alert_detail(alert_id: int) -> dict | None:
    """获取告警详情（含规则、日志、证据）"""
    from app.models.alert import AlertEvidence
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return None

    evidences = AlertEvidence.query.filter_by(alert_id=alert_id).all()
    detail = alert.to_detail_dict()
    detail["evidences"] = [e.to_dict() for e in evidences]
    return detail


def update_alert_status(alert_id: int, new_status: str, comment: str = "", user_id: int = 0, username: str = ""):
    """更新告警状态"""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return False

    valid_statuses = {"new", "in_progress", "confirmed", "false_positive", "closed"}
    if new_status not in valid_statuses:
        return False

    old_status = alert.status
    alert.status = new_status
    if comment:
        if alert.summary:
            alert.summary = f"{alert.summary}\n[{datetime.now(timezone.utc).isoformat()}] {comment}"
        else:
            alert.summary = f"[{datetime.now(timezone.utc).isoformat()}] {comment}"

    # 记录状态变更笔记
    if user_id and username and old_status != new_status:
        try:
            from app.services.comment_service import add_comment
            status_labels = {"new": "新告警", "in_progress": "处理中", "confirmed": "已确认",
                             "false_positive": "误报", "closed": "已关闭"}
            add_comment(
                alert_id=alert.id,
                user_id=user_id,
                username=username,
                content=f"状态变更: {status_labels.get(old_status, old_status)} → {status_labels.get(new_status, new_status)}",
                comment_type="status_change",
                old_status=old_status,
                new_status=new_status,
            )
        except Exception:
            pass

    db.session.commit()
    return True


def batch_update_status(alert_ids: List[int], new_status: str):
    """批量更新告警状态"""
    valid_statuses = {"confirmed", "false_positive", "closed"}
    if new_status not in valid_statuses:
        return 0

    count = Alert.query.filter(Alert.id.in_(alert_ids)).update(
        {"status": new_status},
        synchronize_session="fetch",
    )
    db.session.commit()
    return count


# ── 告警趋势 ──

def get_alert_trend(days: int = 7) -> dict:
    """告警趋势统计"""
    from sqlalchemy import func
    start = datetime.now(timezone.utc) - __import__("datetime").timedelta(days=days)

    by_day = (
        db.session.query(
            func.date(Alert.event_time).label("date"),
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.event_time >= start)
        .group_by(func.date(Alert.event_time))
        .all()
    )

    by_severity = (
        db.session.query(
            Alert.severity,
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.event_time >= start)
        .group_by(Alert.severity)
        .all()
    )

    by_attack_type = (
        db.session.query(
            Alert.attack_type,
            func.count(Alert.id).label("count"),
        )
        .filter(Alert.event_time >= start)
        .group_by(Alert.attack_type)
        .all()
    )

    return {
        "by_day": [{"date": str(row.date), "count": row.count} for row in by_day],
        "by_severity": [{"severity": row.severity, "count": row.count} for row in by_severity],
        "by_attack_type": [{"type": row.attack_type, "count": row.count} for row in by_attack_type],
    }


# ── 告警聚合 ──

def aggregate_alerts(
    src_ip: str | None = None,
    asset: str | None = None,
    time_window_minutes: int | None = None,
) -> AlertEvent | None:
    """将符合条件的告警聚合为安全事件

    聚合条件：同源 IP、同资产、时间窗口内的相关告警
    """
    window = time_window_minutes or _get_time_window_minutes()
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    window_start = now - timedelta(minutes=window)

    query = Alert.query.filter(
        Alert.status.in_(["new", "in_progress", "confirmed"]),
    )

    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)
    if asset:
        query = query.filter(Alert.asset == asset)

    # 时间窗口
    query = query.filter(Alert.event_time >= window_start)
    alerts = query.order_by(Alert.event_time).all()

    if len(alerts) < 2:
        return None  # 单条告警不聚合

    # 计算风险分
    risk_scores = [a.risk_score for a in alerts if a.risk_score]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    max_risk = max(risk_scores) if risk_scores else 0

    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_sev = max(
        (a.severity for a in alerts),
        key=lambda s: severity_levels.get(s, 0),
    )

    # 创建事件
    event = AlertEvent(
        event_no=generate_event_no(),
        title=f"聚合安全事件 - {src_ip or asset or '多源告警'}",
        src_ip=src_ip or alerts[0].src_ip,
        asset=asset or alerts[0].asset,
        severity=max_sev,
        risk_score=int(avg_risk * 0.6 + max_risk * 0.4),
        start_time=alerts[0].event_time,
        end_time=alerts[-1].event_time,
        status="open",
        summary=f"聚合 {len(alerts)} 条相关告警，涉及 {len(set(a.attack_type for a in alerts))} 种攻击类型",
    )
    db.session.add(event)
    db.session.flush()

    # 关联告警到事件
    for alert in alerts:
        db.session.add(EventAlertRelation(event_id=event.id, alert_id=alert.id))
        # 将告警标记为研判中
        if alert.status == "new":
            alert.status = "in_progress"

    db.session.commit()
    return event


# ── 告警去重 ──

def deduplicate_alerts(time_window_minutes: int = 5) -> int:
    """去重：相同规则、相同源 IP、时间窗口内的重复告警只保留一条"""
    from datetime import timedelta
    window_start = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    # 找到重复告警
    duplicates = (
        db.session.query(
            Alert.rule_id,
            Alert.src_ip,
            Alert.attack_type,
            func.count(Alert.id).label("cnt"),
            func.min(Alert.id).label("min_id"),
        )
        .filter(Alert.event_time >= window_start)
        .filter(Alert.status.in_(["new", "in_progress"]))
        .group_by(Alert.rule_id, Alert.src_ip, Alert.attack_type)
        .having(func.count(Alert.id) > 1)
        .all()
    )

    if not duplicates:
        return 0

    deleted = 0
    for rule_id, src_ip, attack_type, cnt, min_id in duplicates:
        keep_id = min_id
        to_delete = Alert.query.filter(
            Alert.rule_id == rule_id,
            Alert.src_ip == src_ip,
            Alert.attack_type == attack_type,
            Alert.event_time >= window_start,
            Alert.id != keep_id,
            Alert.status.in_(["new", "in_progress"]),
        ).all()
        for alert in to_delete:
            # 删除关联证据
            AlertEvidence.query.filter_by(alert_id=alert.id).delete()
            db.session.delete(alert)
            deleted += 1

    db.session.commit()
    return deleted
