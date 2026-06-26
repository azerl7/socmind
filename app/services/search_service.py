"""全局搜索服务"""
from app import db
from app.models.alert import Alert
from app.models.log import RawLog
from app.models.asset import Asset
from app.models.attack_chain import AttackChain


def global_search(query: str, page: int = 1, page_size: int = 20) -> dict:
    """跨模块全局搜索"""
    if not query or len(query.strip()) < 1:
        return {"alerts": [], "logs": [], "assets": [], "chains": []}

    q = query.strip()
    results = {}

    # 1. 搜索告警（按告警编号、标题、源IP、攻击类型）
    alert_query = Alert.query.filter(
        db.or_(
            Alert.alert_no.ilike(f"%{q}%"),
            Alert.title.ilike(f"%{q}%"),
            Alert.src_ip.ilike(f"%{q}%"),
            Alert.dst_ip.ilike(f"%{q}%"),
            Alert.attack_type.ilike(f"%{q}%"),
            Alert.username.ilike(f"%{q}%"),
        )
    )
    total_alerts = alert_query.count()
    alerts = alert_query.order_by(Alert.event_time.desc()).limit(page_size).all()
    results["alerts"] = {
        "items": [{"id": a.id, "alert_no": a.alert_no, "title": a.title,
                    "severity": a.severity, "src_ip": a.src_ip, "status": a.status,
                    "event_time": a.event_time.isoformat() if a.event_time else None}
                  for a in alerts],
        "total": total_alerts,
    }

    # 2. 搜索日志（按IP、URL、内容）
    log_query = RawLog.query.filter(
        db.or_(
            RawLog.src_ip.ilike(f"%{q}%"),
            RawLog.dst_ip.ilike(f"%{q}%"),
            RawLog.url.ilike(f"%{q}%"),
            RawLog.raw_content.ilike(f"%{q}%"),
            RawLog.username.ilike(f"%{q}%"),
        )
    )
    total_logs = log_query.count()
    logs = log_query.order_by(RawLog.event_time.desc()).limit(page_size).all()
    results["logs"] = {
        "items": [{"id": l.id, "log_type": l.log_type, "src_ip": l.src_ip,
                    "url": l.url, "event_time": l.event_time.isoformat() if l.event_time else None}
                  for l in logs],
        "total": total_logs,
    }

    # 3. 搜索资产
    asset_query = Asset.query.filter(
        db.or_(
            Asset.asset_ip.ilike(f"%{q}%"),
            Asset.hostname.ilike(f"%{q}%"),
            Asset.tags.ilike(f"%{q}%"),
            Asset.department.ilike(f"%{q}%"),
        )
    )
    total_assets = asset_query.count()
    assets = asset_query.order_by(Asset.risk_score.desc()).limit(20).all()
    results["assets"] = {
        "items": [{"id": a.id, "asset_ip": a.asset_ip, "asset_type": a.asset_type,
                    "risk_score": a.risk_score, "hostname": a.hostname}
                  for a in assets],
        "total": total_assets,
    }

    # 4. 搜索攻击链
    chain_query = AttackChain.query.filter(
        db.or_(
            AttackChain.chain_no.ilike(f"%{q}%"),
            AttackChain.title.ilike(f"%{q}%"),
            AttackChain.src_ip.ilike(f"%{q}%"),
            AttackChain.target_asset.ilike(f"%{q}%"),
        )
    )
    total_chains = chain_query.count()
    chains = chain_query.order_by(AttackChain.created_at.desc()).limit(20).all()
    results["chains"] = {
        "items": [{"id": c.id, "chain_no": c.chain_no, "title": c.title,
                    "confidence": c.confidence, "risk_score": c.risk_score}
                  for c in chains],
        "total": total_chains,
    }

    return results
