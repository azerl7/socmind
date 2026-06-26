"""用户偏好设置模型"""
from datetime import datetime, timezone
from app import db


class UserPreference(db.Model):
    """用户个性化设置"""
    __tablename__ = "user_preferences"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    pref_key = db.Column(db.String(64), nullable=False)
    pref_value = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("user_id", "pref_key", name="uq_user_pref"),
    )

    def to_dict(self):
        return {
            "pref_key": self.pref_key,
            "pref_value": self.pref_value,
        }
