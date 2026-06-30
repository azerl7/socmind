"""资产关联服务：资产发现、告警关联、横向移动分析"""
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import List

from app import db
from app.models.asset import Asset, AssetRelation
from app.models.alert import Alert
from app.models.log import RawLog


def discover_assets() -> dict:
    """从已有日志和告警中发现并更新资产列表"""
    count = {"created": 0, "updated": 0}

    # 从 RawLog 中提取不重复的目标 IP
    log_ips = db.session.query(RawLog.dst_ip).filter(
        RawLog.dst_ip.isnot(None),
        RawLog.dst_ip != "",
    ).distinct().all()

    # 从 Alert 中提取不重复的源 IP 和目标资产 IP
    alert_ips = set()
    alert_src_ips = db.session.query(Alert.src_ip).filter(
        Alert.src_ip.isnot(None),
        Alert.src_ip != "",
        Alert.src_ip.notin_(["0.0.0.0", "127.0.0.1"]),
    ).distinct().all()

    alert_dst_ips = db.session.query(Alert.dst_ip).filter(
        Alert.dst_ip.isnot(None),
        Alert.dst_ip != "",
    ).distinct().all()

    for (ip,) in alert_src_ips:
        alert_ips.add(ip)
    for (ip,) in alert_dst_ips:
        alert_ips.add(ip)

    all_ips = set()
    for (ip,) in log_ips:
        if ip:
            all_ips.add(ip)
    for ip in alert_ips:
        all_ips.add(ip)

    now = datetime.now(timezone.utc)

    for ip in all_ips:
        existing = Asset.query.filter_by(asset_ip=ip).first()
        if existing:
            existing.last_seen = now
            # 更新告警计数
            alert_cnt = Alert.query.filter(
                (Alert.src_ip == ip) | (Alert.dst_ip == ip)
            ).count()
            existing.alert_count = alert_cnt
            count["updated"] += 1
        else:
            # 判断资产类型
            asset_type = "host"
            # 如果是内网IP段
            parts = ip.split(".")
            if len(parts) == 4:
                first = int(parts[0])
                if first == 10 or (first == 172 and 16 <= int(parts[1]) <= 31) or (first == 192 and parts[1] == "168"):
                    asset_type = "host"
                else:
                    asset_type = "external"

            asset = Asset(
                asset_ip=ip,
                asset_type=asset_type,
                first_seen=now,
                last_seen=now,
                alert_count=0,
                is_active=1,
            )
            db.session.add(asset)
            count["created"] += 1

    db.session.commit()

    # 更新所有资产的风险评分
    _update_risk_scores()

    return count


def _update_risk_scores():
    """更新所有资产的风险评分"""
    assets = Asset.query.all()
    for asset in assets:
        # 基于关联告警数量和严重程度计算
        alerts = Alert.query.filter(
            (Alert.src_ip == asset.asset_ip) | (Alert.dst_ip == asset.asset_ip)
        ).all()
        if not alerts:
            asset.risk_score = 0
            continue

        severity_scores = {"low": 10, "medium": 30, "high": 50, "critical": 80}
        total = 0
        for a in alerts:
            total += severity_scores.get(a.severity, 10)

        avg_score = total / len(alerts)
        count_bonus = min(len(alerts) * 2, 30)
        asset.risk_score = min(int(avg_score + count_bonus), 100)
        asset.alert_count = len(alerts)

    db.session.commit()


def _resolve_target(alert) -> str | None:
    """根据告警字段决定目标标识符。

    优先级:
    1. dst_ip —— IP→IP 攻击拓扑(最直接)
    2. username —— 账号爆破/异常登录类("user:admin")
    3. url —— URL 资源类,提取一级路径("asset:/admin")
    """
    if alert.dst_ip:
        return alert.dst_ip
    if alert.username:
        return f"user:{alert.username}"
    if alert.url:
        # 提取 URL 一级路径(作为资源标识)
        path = alert.url.split("?")[0].split("/")[1] if "/" in alert.url else alert.url
        return f"asset:/{path}" if path else None
    return None


def build_relations(src_ip: str | None = None, time_window_minutes: int | None = None) -> dict:
    """构建资产间的关联关系（攻击拓扑）

    基于告警数据：同一源IP在时间窗口内攻击多个不同目标，形成关联关系。

    Args:
        time_window_minutes: 时间窗口(分钟)。
            None 或 0 = 查询全部历史告警(推荐用于演示数据 / 关联关系是历史累积的)
            具体数值 = 只查最近 N 分钟的告警(生产环境用)
    """
    query = Alert.query
    if time_window_minutes:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=time_window_minutes)
        query = query.filter(Alert.event_time >= window_start)

    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)

    alerts = query.order_by(Alert.event_time).all()

    # 按源IP分组分析多目标攻击
    ip_targets = defaultdict(lambda: defaultdict(list))
    for alert in alerts:
        src = alert.src_ip or "unknown"
        dst = _resolve_target(alert)
        if dst:
            ip_targets[src][dst].append(alert.id)

    relation_count = {"created": 0, "updated": 0}

    for src_ip_val, targets in ip_targets.items():
        if len(targets) < 2:
            continue  # 只攻击一个目标不需要关联

        src_asset = Asset.query.filter_by(asset_ip=src_ip_val).first()
        if not src_asset:
            # 如果源IP不是已知资产，发现它
            src_asset = Asset(
                asset_ip=src_ip_val,
                asset_type="external",
                first_seen=now,
                last_seen=now,
                is_active=1,
            )
            db.session.add(src_asset)
            db.session.flush()

        for dst_ip_val, alert_ids in targets.items():
            dst_asset = Asset.query.filter_by(asset_ip=dst_ip_val).first()
            if not dst_asset:
                parts = dst_ip_val.split(".")
                at = "host" if len(parts) == 4 and int(parts[0]) == 10 else "unknown"
                dst_asset = Asset(
                    asset_ip=dst_ip_val,
                    asset_type=at,
                    first_seen=now,
                    last_seen=now,
                    is_active=1,
                )
                db.session.add(dst_asset)
                db.session.flush()

            # 查找或创建关联
            existing = AssetRelation.query.filter_by(
                src_asset_id=src_asset.id,
                dst_asset_id=dst_asset.id,
            ).first()

            if existing:
                existing.last_seen = now
                existing.alert_ids = ",".join(str(aid) for aid in alert_ids)
                relation_count["updated"] += 1
            else:
                relation = AssetRelation(
                    src_asset_id=src_asset.id,
                    dst_asset_id=dst_asset.id,
                    src_ip=src_ip_val,
                    relation_type="attack",
                    confidence="high" if len(alert_ids) >= 3 else "medium",
                    first_seen=now,
                    last_seen=now,
                    alert_ids=",".join(str(aid) for aid in alert_ids),
                )
                db.session.add(relation)
                relation_count["created"] += 1

    db.session.commit()
    return relation_count


def get_asset_detail(asset_id: int) -> dict | None:
    """获取资产详情，包含关联告警和关系"""
    asset = db.session.get(Asset, asset_id)
    if not asset:
        return None

    # 关联的告警
    alerts = Alert.query.filter(
        (Alert.src_ip == asset.asset_ip) | (Alert.dst_ip == asset.asset_ip)
    ).order_by(Alert.event_time.desc()).limit(50).all()

    # 资产关系
    outgoing = AssetRelation.query.filter_by(src_asset_id=asset.id).all()
    incoming = AssetRelation.query.filter_by(dst_asset_id=asset.id).all()

    return {
        "asset": asset.to_dict(),
        "recent_alerts": [a.to_dict() for a in alerts],
        "outgoing_relations": [r.to_dict() for r in outgoing],
        "incoming_relations": [r.to_dict() for r in incoming],
        "total_alerts": len(alerts),
    }


def get_asset_topology() -> dict:
    """获取资产关联拓扑（用于ECharts关系图）"""
    relations = AssetRelation.query.all()
    assets_seen = set()
    nodes = []
    edges = []

    for rel in relations:
        if rel.src_asset and rel.src_asset.asset_ip not in assets_seen:
            assets_seen.add(rel.src_asset.asset_ip)
            nodes.append({
                "id": rel.src_asset.asset_ip,
                "name": rel.src_asset.asset_ip,
                "symbolSize": min(20 + rel.src_asset.risk_score // 5, 60),
                "category": rel.src_asset.asset_type,
                "risk_score": rel.src_asset.risk_score,
                "itemStyle": {
                    "color": _risk_color(rel.src_asset.risk_score)
                },
            })

        if rel.dst_asset and rel.dst_asset.asset_ip not in assets_seen:
            assets_seen.add(rel.dst_asset.asset_ip)
            nodes.append({
                "id": rel.dst_asset.asset_ip,
                "name": rel.dst_asset.asset_ip,
                "symbolSize": min(20 + rel.dst_asset.risk_score // 5, 60),
                "category": rel.dst_asset.asset_type,
                "risk_score": rel.dst_asset.risk_score,
                "itemStyle": {
                    "color": _risk_color(rel.dst_asset.risk_score)
                },
            })

        edge_color = "#e74c3c" if rel.confidence == "high" else "#f39c12" if rel.confidence == "medium" else "#95a5a6"
        edges.append({
            "source": rel.src_asset.asset_ip,
            "target": rel.dst_asset.asset_ip,
            "label": rel.relation_type,
            "lineStyle": {"color": edge_color, "width": 2 if rel.confidence == "high" else 1},
        })

    return {"nodes": nodes, "edges": edges}


def _risk_color(score: int) -> str:
    if score >= 70:
        return "#e74c3c"
    elif score >= 40:
        return "#f39c12"
    elif score >= 20:
        return "#3498db"
    return "#27ae60"


def list_assets(
    page: int = 1, page_size: int = 20,
    asset_type: str | None = None,
    keyword: str | None = None,
    sort_by: str = "risk_score",
) -> dict:
    """分页查询资产列表"""
    query = Asset.query.filter()

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if keyword:
        query = query.filter(
            db.or_(
                Asset.asset_ip.ilike(f"%{keyword}%"),
                Asset.hostname.ilike(f"%{keyword}%"),
                Asset.tags.ilike(f"%{keyword}%"),
            )
        )

    sort_map = {
        "risk_score": Asset.risk_score.desc(),
        "alert_count": Asset.alert_count.desc(),
        "last_seen": Asset.last_seen.desc(),
        "first_seen": Asset.first_seen.desc(),
        "asset_ip": Asset.asset_ip.asc(),
    }
    order = sort_map.get(sort_by, Asset.risk_score.desc())

    pagination = query.order_by(order).paginate(
        page=page, per_page=page_size, error_out=False
    )

    return {
        "items": [a.to_dict() for a in pagination.items],
        "page": page,
        "page_size": page_size,
        "total": pagination.total,
    }


def correlate_with_chain(chain_id: int) -> dict:
    """将攻击链与资产关联数据结合"""
    from app.models.attack_chain import AttackChain, AttackChainNode

    chain = db.session.get(AttackChain, chain_id)
    if not chain:
        return {"chain_id": chain_id, "assets": [], "relations": []}

    nodes = AttackChainNode.query.filter_by(chain_id=chain_id).all()
    alert_ids = [n.alert_id for n in nodes if n.alert_id]
    alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all() if alert_ids else []

    # 提取资产
    asset_ips = set()
    for a in alerts:
        if a.src_ip:
            asset_ips.add(a.src_ip)
        if a.dst_ip:
            asset_ips.add(a.dst_ip)

    assets = Asset.query.filter(Asset.asset_ip.in_(asset_ips)).all() if asset_ips else []
    relations = AssetRelation.query.filter(
        db.or_(
            AssetRelation.src_ip.in_(asset_ips),
            AssetRelation.src_asset.has(Asset.asset_ip.in_(asset_ips)),
            AssetRelation.dst_asset.has(Asset.asset_ip.in_(asset_ips)),
        )
    ).all() if asset_ips else []

    return {
        "chain_id": chain_id,
        "assets": [a.to_dict() for a in assets],
        "relations": [r.to_dict() for r in relations],
    }


