"""资产与资产关联模型"""
from datetime import datetime, timezone
from app import db


class Asset(db.Model):
    """被监控资产（主机、服务、应用等）"""
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    asset_ip = db.Column(db.String(64), nullable=False, index=True, comment="资产IP")
    hostname = db.Column(db.String(128), nullable=True, comment="主机名")
    asset_type = db.Column(db.String(32), nullable=False, default="host",
                           comment="host/webapp/database/network")
    os_info = db.Column(db.String(128), nullable=True, comment="操作系统信息")
    department = db.Column(db.String(64), nullable=True, comment="所属部门")
    criticality = db.Column(db.String(16), default="medium",
                            comment="低/中/高/严重 low/medium/high/critical")
    tags = db.Column(db.String(256), nullable=True, comment="标签")
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    alert_count = db.Column(db.Integer, default=0, comment="关联告警数")
    risk_score = db.Column(db.Integer, default=0, comment="资产风险分")
    is_active = db.Column(db.SmallInteger, default=1)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("idx_asset_ip", "asset_ip"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "asset_ip": self.asset_ip,
            "hostname": self.hostname,
            "asset_type": self.asset_type,
            "os_info": self.os_info,
            "department": self.department,
            "criticality": self.criticality,
            "tags": self.tags.split(",") if self.tags else [],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "alert_count": self.alert_count,
            "risk_score": self.risk_score,
            "is_active": bool(self.is_active),
        }


class AssetRelation(db.Model):
    """资产间关联关系（攻击链路中的横向移动路径）"""
    __tablename__ = "asset_relations"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    src_asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    dst_asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    relation_type = db.Column(db.String(32), default="attack",
                              comment="attack/lateral/access/scan")
    src_ip = db.Column(db.String(64), nullable=True, comment="攻击源IP")
    confidence = db.Column(db.String(16), default="medium", comment="关联可信度")
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    alert_ids = db.Column(db.Text, nullable=True, comment="关联告警ID列表")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    src_asset = db.relationship("Asset", foreign_keys=[src_asset_id], lazy="joined")
    dst_asset = db.relationship("Asset", foreign_keys=[dst_asset_id], lazy="joined")

    def to_dict(self):
        return {
            "id": self.id,
            "src_asset": self.src_asset.to_dict() if self.src_asset else None,
            "dst_asset": self.dst_asset.to_dict() if self.dst_asset else None,
            "relation_type": self.relation_type,
            "src_ip": self.src_ip,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "alert_count": len((self.alert_ids or "").split(",")) if self.alert_ids else 0,
        }
