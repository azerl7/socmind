"""检测规则模型"""
from datetime import datetime, timezone
from sqlalchemy import JSON
from app import db


class DetectionRule(db.Model):
    __tablename__ = "detection_rules"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule_code = db.Column(db.String(64), unique=True, nullable=False)
    rule_name = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(64), nullable=False, index=True,
                         comment="web/account/host/network")
    attack_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, comment="low/medium/high/critical")
    rule_pattern = db.Column(db.Text, nullable=True, comment="正则或匹配规则")
    rule_config = db.Column(JSON, nullable=True, comment="规则配置")
    stage_code = db.Column(db.String(64), nullable=True, comment="默认攻击阶段")
    enabled = db.Column(db.SmallInteger, default=1, comment="1启用 0禁用")
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "rule_code": self.rule_code,
            "rule_name": self.rule_name,
            "category": self.category,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "rule_pattern": self.rule_pattern,
            "rule_config": self.rule_config,
            "stage_code": self.stage_code,
            "enabled": bool(self.enabled),
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
