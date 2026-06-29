"""审计日志服务:统一封装 AuditLog 记录"""
import logging

from flask_login import current_user
from app import db
from app.models.config import AuditLog

logger = logging.getLogger(__name__)


def record_audit(action: str, target_type: str = None, target_id: int = None,
                 detail: dict = None) -> None:
    """记录一条审计日志(失败不影响主业务,异常静默记日志)

    Args:
        action: 操作类型,如 'alert_status_changed' / 'login_success'
        target_type: 操作对象类型,如 'alert' / 'config' / 'rule'
        target_id: 操作对象 ID
        detail: 操作详情(dict,会存到 JSON 字段)
    """
    try:
        # 从 flask_login 取当前用户
        try:
            user_id = current_user.id if current_user.is_authenticated else None
            username = current_user.username if current_user.is_authenticated else None
        except Exception:
            user_id = None
            username = None

        log = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
            ip_address=None,  # 如需记录 IP 可从 request.remote_addr 取
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # 审计日志失败不影响主业务,但要记到日志便于排查
        logger.error(f"记录审计日志失败 (action={action}): {e}", exc_info=True)