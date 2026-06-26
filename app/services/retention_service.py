"""数据保留与清理服务：自动清理过期数据"""
import logging
from datetime import datetime, timedelta, timezone

from app import db
from app.models.log import RawLog
from app.models.alert import Alert, AlertEvidence, AlertTagRelation, EventAlertRelation
from app.models.attack_chain import AttackChain, AttackChainNode
from app.models.ai_analysis import AIAnalysis
from app.models.config import SystemConfig, AuditLog
from app.models.login_log import LoginLog
from app.models.comment import AlertComment

logger = logging.getLogger(__name__)


def _get_config(key: str, default: str = "") -> str:
    config = SystemConfig.query.filter_by(config_key=key).first()
    return config.config_value if config and config.config_value else default


def purge_old_data() -> dict:
    """清理过期数据"""
    results = {}

    # 读取保留配置（默认天数）
    raw_log_days = int(_get_config("retention_raw_logs", "90"))
    alert_days = int(_get_config("retention_alerts", "365"))
    login_log_days = int(_get_config("retention_login_logs", "180"))
    audit_log_days = int(_get_config("retention_audit_logs", "365"))

    now = datetime.now(timezone.utc)

    # 1. 清理原始日志
    if raw_log_days > 0:
        cutoff = now - timedelta(days=raw_log_days)
        deleted = RawLog.query.filter(RawLog.event_time < cutoff).delete()
        results["raw_logs"] = deleted
        logger.info(f"[保留策略] 已清理 {deleted} 条原始日志 (>{raw_log_days}天)")

    # 2. 清理已关闭的告警（保留摘要）
    if alert_days > 0:
        cutoff = now - timedelta(days=alert_days)
        old_alerts = Alert.query.filter(
            Alert.status.in_(["closed", "false_positive"]),
            Alert.event_time < cutoff,
        ).all()

        alert_ids = [a.id for a in old_alerts]
        if alert_ids:
            # 清理关联数据
            AlertEvidence.query.filter(AlertEvidence.alert_id.in_(alert_ids)).delete()
            AlertTagRelation.query.filter(AlertTagRelation.alert_id.in_(alert_ids)).delete()
            EventAlertRelation.query.filter(EventAlertRelation.alert_id.in_(alert_ids)).delete()
            AlertComment.query.filter(AlertComment.alert_id.in_(alert_ids)).delete()
            AIAnalysis.query.filter(AIAnalysis.alert_id.in_(alert_ids)).delete()

            for alert in old_alerts:
                db.session.delete(alert)

        results["alerts"] = len(alert_ids)
        logger.info(f"[保留策略] 已清理 {len(alert_ids)} 条历史告警 (>{alert_days}天)")

    # 3. 清理登录日志
    if login_log_days > 0:
        cutoff = now - timedelta(days=login_log_days)
        deleted = LoginLog.query.filter(LoginLog.created_at < cutoff).delete()
        results["login_logs"] = deleted

    # 4. 清理审计日志
    if audit_log_days > 0:
        cutoff = now - timedelta(days=audit_log_days)
        deleted = AuditLog.query.filter(AuditLog.created_at < cutoff).delete()
        results["audit_logs"] = deleted

    # 5. 清理孤立攻击链节点
    orphaned_nodes = AttackChainNode.query.filter(
        ~AttackChainNode.chain_id.in_(
            db.session.query(AttackChain.id)
        )
    ).delete()
    results["orphaned_nodes"] = orphaned_nodes

    db.session.commit()

    total = sum(results.values())
    logger.info(f"[保留策略] 本轮清理完成，共删除 {total} 条记录")
    results["total_deleted"] = total
    return results
