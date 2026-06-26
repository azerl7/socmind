"""仪表盘数据接口：聚合统计数据"""
from flask import Blueprint, jsonify, request
from app import db
from app.models.log import RawLog
from app.models.alert import Alert
from app.models.attack_chain import AttackChain
from app.models.report import Report
from app.utils.response import success_response
from datetime import datetime, timedelta, timezone

dashboard_bp = Blueprint("dashboard_routes", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
def stats():
    """聚合仪表盘统计数据"""
    from app.services.metrics_service import get_platform_metrics

    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)

    # 日志总数
    log_count = RawLog.query.count()
    log_today = RawLog.query.filter(RawLog.created_at >= (now - timedelta(days=1))).count()

    # 告警总数
    alert_count = Alert.query.count()
    alert_high = Alert.query.filter(Alert.severity.in_(["high", "critical"])).count()
    alert_new = Alert.query.filter(Alert.status == "new").count()
    alert_week = Alert.query.filter(Alert.event_time >= week_ago).count()

    # 攻击链
    chain_count = AttackChain.query.count()

    # 报告
    report_count = Report.query.count()

    # 最近活动
    recent_alerts = Alert.query.order_by(Alert.event_time.desc()).limit(5).all()

    return jsonify(success_response({
        "logs": {
            "total": log_count,
            "today": log_today,
        },
        "alerts": {
            "total": alert_count,
            "high_risk": alert_high,
            "unhandled": alert_new,
            "this_week": alert_week,
        },
        "attack_chains": {
            "total": chain_count,
        },
        "reports": {
            "total": report_count,
        },
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "attack_type": a.attack_type,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "src_ip": a.src_ip,
                "status": a.status,
                "event_time": a.event_time.isoformat() if a.event_time else None,
            }
            for a in recent_alerts
        ],
    }))


@dashboard_bp.route("/metrics", methods=["GET"])
def platform_metrics():
    """获取平台运行指标"""
    from app.services.metrics_service import get_platform_metrics
    days = request.args.get("days", 7, type=int)
    data = get_platform_metrics(days=days)
    return jsonify(success_response(data))
