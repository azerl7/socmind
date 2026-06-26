"""攻击链模型"""
from datetime import datetime, timezone
from sqlalchemy import Text
from app import db


class AttackStage(db.Model):
    __tablename__ = "attack_stages"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stage_code = db.Column(db.String(64), unique=True, nullable=False)
    stage_name = db.Column(db.String(128), nullable=False)
    stage_order = db.Column(db.Integer, nullable=False)
    framework = db.Column(db.String(64), nullable=False, comment="web_chain/mitre_attack")
    description = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "stage_code": self.stage_code,
            "stage_name": self.stage_name,
            "stage_order": self.stage_order,
            "framework": self.framework,
            "description": self.description,
        }


class AttackChain(db.Model):
    __tablename__ = "attack_chains"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    chain_no = db.Column(db.String(64), unique=True, nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("alert_events.id"), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    src_ip = db.Column(db.String(64), nullable=True)
    target_asset = db.Column(db.String(255), nullable=True)
    stage_count = db.Column(db.Integer, default=0)
    confidence = db.Column(db.String(16), default="medium", comment="high/medium/low")
    risk_score = db.Column(db.Integer, default=0)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    ai_summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    nodes = db.relationship("AttackChainNode", backref="chain", lazy="select",
                            order_by="AttackChainNode.sort_order")

    def to_dict(self):
        return {
            "id": self.id,
            "chain_no": self.chain_no,
            "event_id": self.event_id,
            "title": self.title,
            "src_ip": self.src_ip,
            "target_asset": self.target_asset,
            "stage_count": self.stage_count,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "ai_summary": self.ai_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_detail_dict(self):
        d = self.to_dict()
        d["nodes"] = [n.to_dict() for n in self.nodes]
        return d


class AttackChainNode(db.Model):
    __tablename__ = "attack_chain_nodes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    chain_id = db.Column(db.Integer, db.ForeignKey("attack_chains.id"), nullable=False)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=True)
    raw_log_id = db.Column(db.Integer, db.ForeignKey("raw_logs.id"), nullable=True)
    stage_code = db.Column(db.String(64), nullable=False, index=True)
    node_title = db.Column(db.String(255), nullable=False)
    node_desc = db.Column(db.Text, nullable=True)
    evidence = db.Column(Text, nullable=True)
    event_time = db.Column(db.DateTime, nullable=True, index=True)
    sort_order = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "chain_id": self.chain_id,
            "alert_id": self.alert_id,
            "raw_log_id": self.raw_log_id,
            "stage_code": self.stage_code,
            "node_title": self.node_title,
            "node_desc": self.node_desc,
            "evidence": self.evidence,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "sort_order": self.sort_order,
        }
