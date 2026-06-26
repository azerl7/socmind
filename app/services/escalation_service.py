"""告警升级服务：未处理的严重告警自动升级"""
import logging
from datetime import datetime, timedelta, timezone

from app import db
from app.models.alert import Alert
from app.models.config import SystemConfig

logger = logging.getLogger(__name__)


def _get_config(key: str, default: str = "") -> str:
    config = SystemConfig.query.filter_by(config_key=key).first()
    return config.config_value if config and config.config_value else default


def check_escalations() -> dict:
    """检查并执行告警升级

    对所有超过升级阈值的未处理告警执行升级操作
    """
    # 读取升级配置
    enabled = _get_config("escalation_enabled", "false")
    if enabled != "true":
        return {"enabled": False, "escalated": 0}

    critical_hours = int(_get_config("escalation_critical_hours", "1"))
    high_hours = int(_get_config("escalation_high_hours", "4"))
    medium_hours = int(_get_config("escalation_medium_hours", "12"))
    max_escalations = int(_get_config("escalation_max_count", "3"))

    now = datetime.now(timezone.utc)
    escalated = 0

    # 检查严重告警
    for severity, hours in [("critical", critical_hours), ("high", high_hours), ("medium", medium_hours)]:
        if hours <= 0:
            continue

        threshold_time = now - timedelta(hours=hours)
        alerts = Alert.query.filter(
            Alert.severity == severity,
            Alert.status.in_(["new", "in_progress"]),
            Alert.event_time <= threshold_time,
        ).all()

        for alert in alerts:
            # 检查升级次数限制
            escalation_count = _get_escalation_count(alert)
            if escalation_count >= max_escalations:
                continue

            _escalate_alert(alert, severity, hours, escalation_count + 1)
            escalated += 1

    db.session.commit()

    if escalated:
        logger.info(f"[升级服务] 已升级 {escalated} 条告警")

    return {"enabled": True, "escalated": escalated}


def _get_escalation_count(alert: Alert) -> int:
    """获取告警已升级次数（通过评论记录）"""
    try:
        from app.models.comment import AlertComment
        count = AlertComment.query.filter(
            AlertComment.alert_id == alert.id,
            AlertComment.comment_type == "escalation",
        ).count()
        return count
    except Exception:
        return 0


def _escalate_alert(alert: Alert, severity: str, hours: int, escalation_num: int):
    """执行单条告警升级"""
    # 记录升级前状态
    old_status = alert.status

    # 升级严重等级
    severity_escalation = {
        "critical": "critical",
        "high": "critical",
        "medium": "high",
        "low": "medium",
    }
    new_severity = severity_escalation.get(severity, severity)

    # 更新告警
    alert.severity = new_severity
    if alert.risk_score:
        alert.risk_score = min(alert.risk_score + 10, 100)

    # 添加升级评论
    try:
        from app.services.comment_service import add_comment
        add_comment(
            alert_id=alert.id,
            user_id=0,
            username="system",
            content=f"⚠ 自动升级 (第{escalation_num}次): 告警超过 {hours} 小时未处理，"
                    f"严重等级从 {severity.upper()} 升级至 {new_severity.upper()}",
            comment_type="escalation",
            old_status=old_status,
            new_status=alert.status,
        )
    except Exception:
        pass

    # 发送通知
    _send_escalation_notification(alert, escalation_num)


def _send_escalation_notification(alert: Alert, escalation_num: int):
    """发送升级通知"""
    try:
        from app.services.notification_service import notify_alert
        notify_alert(alert.id, force=True)
    except Exception as e:
        logger.warning(f"[升级服务] 通知失败: {e}")


def run_escalation_check() -> dict:
    """供调度器调用的升级检查入口"""
    try:
        return check_escalations()
    except Exception as e:
        logger.error(f"[升级服务] 执行异常: {e}")
        return {"error": str(e)}
