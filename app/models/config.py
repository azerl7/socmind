"""系统配置与审计模型"""
from datetime import datetime, timezone
from sqlalchemy import JSON, Text
from app import db


class SystemConfig(db.Model):
    __tablename__ = "system_configs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    config_key = db.Column(db.String(128), unique=True, nullable=False)
    config_value = db.Column(db.Text, nullable=True)
    config_type = db.Column(db.String(32), default="string", comment="string/json/secret/number")
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "config_key": self.config_key,
            "config_value": self.config_value,
            "config_type": self.config_type,
            "description": self.description,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(128), nullable=False, comment="操作类型")
    target_type = db.Column(db.String(64), nullable=True, comment="操作对象类型")
    target_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(JSON, nullable=True, comment="操作详情")
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "detail": self.detail,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AICallLog(db.Model):
    __tablename__ = "ai_call_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    target_type = db.Column(db.String(32), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    model_name = db.Column(db.String(128), nullable=True)
    prompt_tokens = db.Column(db.Integer, nullable=True, comment="输入 Token 数")
    completion_tokens = db.Column(db.Integer, nullable=True, comment="输出 Token 数")
    total_tokens = db.Column(db.Integer, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True, comment="调用耗时(ms)")
    status = db.Column(db.String(32), nullable=False, default="success",
                       comment="success/failed/fallback")
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
