"""平台指标统计服务"""
from datetime import datetime, timedelta, timezone
from sqlalchemy import func

from app import db
from app.models.alert import Alert
from app.models.attack_chain import AttackChain
from app.models.log import RawLog
from app.models.asset import Asset
from app.models.comment import AlertComment


def get_platform_metrics(days: int = 7) -> dict:
    """获取平台运行指标"""
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    # 告警相关统计
    total_alerts = Alert.query.count()
    alerts_in_window = Alert.query.filter(Alert.event_time >= window_start)
    new_alerts = alerts_in_window.filter(Alert.status == "new").count()
    closed_alerts = alerts_in_window.filter(Alert.status == "closed").count()
    fp_alerts = alerts_in_window.filter(Alert.status == "false_positive").count()
    critical_alerts = alerts_in_window.filter(Alert.severity == "critical").count()

    # 各等级统计
    severity_counts = dict(
        alerts_in_window.with_entities(
            Alert.severity, func.count(Alert.id)
        ).group_by(Alert.severity).all()
    )

    # 平均处置时间（从创建到关闭）
    avg_resolution = db.session.query(
        func.avg(
            func.extract('epoch', Alert.updated_at - Alert.event_time) / 3600
        )
    ).filter(
        Alert.status == "closed",
        Alert.event_time >= window_start,
    ).scalar()

    # 攻击链统计
    chains_in_window = AttackChain.query.filter(
        AttackChain.created_at >= window_start
    )
    chain_count = chains_in_window.count()
    high_confidence_chains = chains_in_window.filter(
        AttackChain.confidence == "high"
    ).count()

    # 日志统计
    log_count = RawLog.query.filter(
        RawLog.event_time >= window_start
    ).count()

    log_by_type = dict(
        RawLog.query.with_entities(
            RawLog.log_type, func.count(RawLog.id)
        ).filter(
            RawLog.event_time >= window_start
        ).group_by(RawLog.log_type).all()
    )

    # 资产统计
    asset_count = Asset.query.count()
    high_risk_assets = Asset.query.filter(Asset.risk_score >= 70).count()

    # 人工处置统计
    comment_count = AlertComment.query.filter(
        AlertComment.created_at >= window_start
    ).count()
    analyst_actions = AlertComment.query.filter(
        AlertComment.comment_type == "status_change",
        AlertComment.created_at >= window_start,
    ).count()

    return {
        "period_days": days,
        "alerts": {
            "total": total_alerts,
            "new": new_alerts,
            "closed": closed_alerts,
            "false_positive": fp_alerts,
            "critical": critical_alerts,
            "by_severity": severity_counts,
            "avg_resolution_hours": round(float(avg_resolution or 0), 1),
        },
        "attack_chains": {
            "total": chain_count,
            "high_confidence": high_confidence_chains,
            "confidence_rate": round(high_confidence_chains / max(chain_count, 1) * 100, 1),
        },
        "logs": {
            "total_in_window": log_count,
            "by_type": log_by_type,
        },
        "assets": {
            "total": asset_count,
            "high_risk": high_risk_assets,
        },
        "operations": {
            "comments": comment_count,
            "analyst_actions": analyst_actions,
        },
        "generated_at": now.isoformat(),
    }
