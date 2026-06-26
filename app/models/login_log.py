"""登录日志模型"""
from datetime import datetime, timezone
from app import db


class LoginLog(db.Model):
    """登录尝试记录"""
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    user_agent = db.Column(db.String(256), nullable=True)
    result = db.Column(db.String(16), nullable=False, comment="success/fail")
    fail_reason = db.Column(db.String(64), nullable=True, comment="失败原因")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "result": self.result,
            "fail_reason": self.fail_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
