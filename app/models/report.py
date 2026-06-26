"""报告模型"""
from datetime import datetime, timezone
from sqlalchemy import Text
from app import db


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    report_no = db.Column(db.String(64), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(32), nullable=False, index=True,
                            comment="alert/event/chain/summary")
    target_id = db.Column(db.Integer, nullable=True)
    content_md = db.Column(Text, nullable=True)
    content_html = db.Column(Text, nullable=True)
    file_path = db.Column(db.String(512), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "report_no": self.report_no,
            "title": self.title,
            "report_type": self.report_type,
            "target_id": self.target_id,
            "content_md": self.content_md[:200] + "..." if self.content_md and len(self.content_md) > 200 else self.content_md,
            "content_html": self.content_html[:200] + "..." if self.content_html and len(self.content_html) > 200 else self.content_html,
            "file_path": self.file_path,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ReportTemplate(db.Model):
    __tablename__ = "report_templates"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    template_name = db.Column(db.String(128), nullable=False)
    template_type = db.Column(db.String(32), nullable=False, index=True)
    content = db.Column(Text, nullable=False, comment="模板内容")
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)
