"""告警评论/协作模型"""
from datetime import datetime, timezone
from app import db


class AlertComment(db.Model):
    """告警分析评论"""
    __tablename__ = "alert_comments"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=False, comment="用户ID")
    username = db.Column(db.String(64), nullable=False, comment="用户名")
    content = db.Column(db.Text, nullable=False, comment="评论内容")
    comment_type = db.Column(db.String(16), default="comment",
                              comment="comment/status_change/investigation")
    old_status = db.Column(db.String(16), nullable=True)
    new_status = db.Column(db.String(16), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "user_id": self.user_id,
            "username": self.username,
            "content": self.content,
            "comment_type": self.comment_type,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
