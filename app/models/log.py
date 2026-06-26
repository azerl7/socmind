"""日志与导入任务模型"""
from datetime import datetime, timezone
from sqlalchemy import Text, JSON
from app import db


class RawLog(db.Model):
    """原始日志表"""
    __tablename__ = "raw_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    import_task_id = db.Column(db.Integer, db.ForeignKey("log_import_tasks.id"), nullable=True)
    log_type = db.Column(db.String(32), nullable=False, index=True,
                         comment="web/login/waf/host/network")
    source = db.Column(db.String(64), nullable=True)
    event_time = db.Column(db.DateTime, nullable=True, index=True)
    src_ip = db.Column(db.String(64), nullable=True, index=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_ip = db.Column(db.String(64), nullable=True, index=True)
    dst_port = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(128), nullable=True)
    http_method = db.Column(db.String(16), nullable=True)
    url = db.Column(db.Text, nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    action = db.Column(db.String(64), nullable=True)
    result = db.Column(db.String(32), nullable=True, comment="success/fail/unknown")
    raw_content = db.Column(Text, nullable=False)
    parsed_json = db.Column(JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # 索引建议由迁移脚本统一创建
    __table_args__ = (
        db.Index("idx_rawlog_type_time", "log_type", "event_time"),
        db.Index("idx_rawlog_src_ip_time", "src_ip", "event_time"),
        db.Index("idx_rawlog_dst_ip_time", "dst_ip", "event_time"),
        db.Index("idx_rawlog_username_time", "username", "event_time"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "import_task_id": self.import_task_id,
            "log_type": self.log_type,
            "source": self.source,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "username": self.username,
            "http_method": self.http_method,
            "url": self.url,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "action": self.action,
            "result": self.result,
            "parsed_json": self.parsed_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LogImportTask(db.Model):
    """日志导入任务表"""
    __tablename__ = "log_import_tasks"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    log_type = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending",
                       comment="pending/running/success/failed")
    total_count = db.Column(db.Integer, default=0)
    success_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "log_type": self.log_type,
            "status": self.status,
            "total_count": self.total_count,
            "success_count": self.success_count,
            "failed_count": self.failed_count,
            "error_message": self.error_message,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
