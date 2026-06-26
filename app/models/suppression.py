"""告警抑制规则模型：IP 白名单、规则级抑制、攻击类型过滤"""
from datetime import datetime, timezone
from app import db


class AlertSuppression(db.Model):
    """告警抑制规则"""
    __tablename__ = "alert_suppressions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule_name = db.Column(db.String(128), nullable=False, comment="规则名称")
    match_type = db.Column(db.String(32), nullable=False, default="ip",
                           comment="ip/attack_type/severity/rule_code/combination")
    match_value = db.Column(db.String(256), nullable=False, comment="匹配值")
    reason = db.Column(db.String(256), nullable=True, comment="理由")
    expires_at = db.Column(db.DateTime, nullable=True, comment="过期时间")
    is_active = db.Column(db.SmallInteger, default=1)
    created_by = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    hit_count = db.Column(db.Integer, default=0, comment="命中次数")
    last_hit_at = db.Column(db.DateTime, nullable=True, comment="最后命中时间")

    def to_dict(self):
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "match_type": self.match_type,
            "match_value": self.match_value,
            "reason": self.reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": bool(self.is_active),
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "hit_count": self.hit_count,
            "last_hit_at": self.last_hit_at.isoformat() if self.last_hit_at else None,
        }
