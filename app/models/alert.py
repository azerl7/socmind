"""告警与事件模型"""
from datetime import datetime, timezone
from sqlalchemy import Text
from app import db


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_no = db.Column(db.String(64), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey("detection_rules.id"), nullable=True)
    raw_log_id = db.Column(db.Integer, db.ForeignKey("raw_logs.id"), nullable=True)
    attack_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, index=True)
    risk_score = db.Column(db.Integer, default=0, index=True)
    src_ip = db.Column(db.String(64), nullable=True, index=True)
    dst_ip = db.Column(db.String(64), nullable=True, index=True)
    username = db.Column(db.String(128), nullable=True)
    asset = db.Column(db.String(255), nullable=True)
    event_time = db.Column(db.DateTime, nullable=True, index=True)
    status = db.Column(db.String(32), nullable=False, default="new", index=True)
    assigned_to = db.Column(db.Integer, nullable=True)
    assigned_username = db.Column(db.String(64), nullable=True)
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    rule = db.relationship("DetectionRule", backref="alerts", lazy="select")
    raw_log = db.relationship("RawLog", backref="alerts", lazy="select")
    __table_args__ = (
        db.Index("idx_alert_status_severity", "status", "severity"),
        db.Index("idx_alert_event_time_status", "event_time", "status"),
        db.Index("idx_alert_src_ip_event_time", "src_ip", "event_time"),
    )

    def to_dict(self):
        return {
            "id": self.id, "alert_no": self.alert_no, "title": self.title,
            "rule_id": self.rule_id, "raw_log_id": self.raw_log_id,
            "attack_type": self.attack_type, "severity": self.severity,
            "risk_score": self.risk_score, "src_ip": self.src_ip,
            "dst_ip": self.dst_ip, "username": self.username, "asset": self.asset,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "status": self.status, "summary": self.summary,
            "assigned_to": self.assigned_to, "assigned_username": self.assigned_username,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_detail_dict(self):
        d = self.to_dict()
        d["rule"] = self.rule.to_dict() if self.rule else None
        d["raw_log"] = self.raw_log.to_dict() if self.raw_log else None
        return d


class AlertEvidence(db.Model):
    __tablename__ = "alert_evidences"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False)
    evidence_type = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    def to_dict(self):
        return {"id": self.id, "alert_id": self.alert_id,
                "evidence_type": self.evidence_type, "title": self.title,
                "content": self.content,
                "created_at": self.created_at.isoformat() if self.created_at else None}


class AlertEvent(db.Model):
    __tablename__ = "alert_events"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_no = db.Column(db.String(64), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    src_ip = db.Column(db.String(64), nullable=True)
    asset = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(16), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    start_time = db.Column(db.DateTime, nullable=True, index=True)
    end_time = db.Column(db.DateTime, nullable=True, index=True)
    status = db.Column(db.String(32), nullable=False, default="open", index=True)
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    def to_dict(self):
        return {"id": self.id, "event_no": self.event_no, "title": self.title,
                "src_ip": self.src_ip, "asset": self.asset,
                "severity": self.severity, "risk_score": self.risk_score,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "status": self.status, "summary": self.summary,
                "created_at": self.created_at.isoformat() if self.created_at else None,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None}


class EventAlertRelation(db.Model):
    __tablename__ = "event_alert_relations"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_id = db.Column(db.Integer, db.ForeignKey("alert_events.id"), nullable=False)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("event_id", "alert_id"),)


class AlertTag(db.Model):
    __tablename__ = "alert_tags"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tag_name = db.Column(db.String(64), unique=True, nullable=False)
    tag_color = db.Column(db.String(16), default="primary")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    def to_dict(self):
        return {"id": self.id, "tag_name": self.tag_name, "tag_color": self.tag_color}


class AlertTagRelation(db.Model):
    __tablename__ = "alert_tag_relations"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey("alert_tags.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint("alert_id", "tag_id"),)
