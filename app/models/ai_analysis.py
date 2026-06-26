"""AI 研判结果模型"""
from datetime import datetime, timezone
from sqlalchemy import Text, JSON
from app import db


class AIAnalysis(db.Model):
    __tablename__ = "ai_analyses"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    target_type = db.Column(db.String(32), nullable=False, index=True,
                            comment="alert/event/chain/report")
    target_id = db.Column(db.Integer, nullable=False, index=True)
    model_name = db.Column(db.String(128), nullable=True)
    prompt = db.Column(Text, nullable=True)
    result_json = db.Column(JSON, nullable=True, comment="结构化结果")
    summary = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(16), nullable=True)
    suggestion = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="success", index=True,
                       comment="success/failed/fallback")
    error_message = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # AI-08: 人工修订支持
    is_revised = db.Column(db.Boolean, default=False, comment="是否被人工修订")
    revised_by = db.Column(db.Integer, nullable=True, comment="修订人ID")
    revised_by_name = db.Column(db.String(64), nullable=True, comment="修订人姓名")
    revised_at = db.Column(db.DateTime, nullable=True, comment="修订时间")
    revision_comment = db.Column(db.Text, nullable=True, comment="修订说明")

    def to_dict(self):
        return {
            "id": self.id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "model_name": self.model_name,
            "summary": self.summary,
            "risk_level": self.risk_level,
            "suggestion": self.suggestion,
            "result_json": self.result_json,
            "status": self.status,
            "error_message": self.error_message,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            # AI-08 修订字段
            "is_revised": self.is_revised,
            "revised_by": self.revised_by,
            "revised_by_name": self.revised_by_name,
            "revised_at": self.revised_at.isoformat() if self.revised_at else None,
            "revision_comment": self.revision_comment,
        }
