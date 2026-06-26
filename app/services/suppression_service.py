"""告警抑制服务：检测告警是否应被抑制"""
from datetime import datetime, timezone

from app import db
from app.models.suppression import AlertSuppression
from app.models.alert import Alert
from app.models.log import RawLog


# 缓存抑制规则
_suppression_cache: list | None = None
_cache_time: datetime | None = None
CACHE_TTL = 60


def _load_rules() -> list:
    """加载激活的抑制规则（带缓存）"""
    global _suppression_cache, _cache_time
    now = datetime.now(timezone.utc)

    if _suppression_cache is None or (
        _cache_time and (now - _cache_time).total_seconds() > CACHE_TTL
    ):
        _suppression_cache = AlertSuppression.query.filter(
            AlertSuppression.is_active == 1,
            db.or_(
                AlertSuppression.expires_at.is_(None),
                AlertSuppression.expires_at > now,
            )
        ).all()
        _cache_time = now

    return _suppression_cache


def invalidate_cache():
    """使抑制规则缓存失效"""
    global _suppression_cache, _cache_time
    _suppression_cache = None
    _cache_time = None


def check_suppression(alert_data: dict) -> dict | None:
    """检查告警是否应被抑制

    Args:
        alert_data: 包含 src_ip, attack_type, severity, rule_code, dst_ip 等

    Returns:
        匹配的抑制规则信息或 None
    """
    rules = _load_rules()
    if not rules:
        return None

    for rule in rules:
        if _matches(rule, alert_data):
            # 更新命中计数
            rule.hit_count = (rule.hit_count or 0) + 1
            rule.last_hit_at = datetime.now(timezone.utc)
            db.session.commit()
            return {
                "suppressed": True,
                "rule_id": rule.id,
                "rule_name": rule.rule_name,
                "reason": rule.reason or "匹配抑制规则",
            }

    return None


def _matches(rule: AlertSuppression, alert_data: dict) -> bool:
    """判断告警是否匹配抑制规则"""
    val = rule.match_value.lower()
    match_type = rule.match_type

    if match_type == "ip":
        return alert_data.get("src_ip", "").lower() == val

    elif match_type == "attack_type":
        return alert_data.get("attack_type", "").lower() == val

    elif match_type == "severity":
        return alert_data.get("severity", "").lower() == val

    elif match_type == "rule_code":
        return alert_data.get("rule_code", "").lower() == val

    elif match_type == "dst_ip":
        return alert_data.get("dst_ip", "").lower() == val

    elif match_type == "combination":
        # 组合条件: ip=1.2.3.4,type=Scanning
        parts = val.split(",")
        for part in parts:
            part = part.strip()
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip().lower()

            field_map = {"ip": "src_ip", "type": "attack_type",
                         "severity": "severity", "rule": "rule_code"}
            field = field_map.get(key)
            if not field:
                continue
            if alert_data.get(field, "").lower() != value:
                return False
        return True

    return False


def list_suppressions(page: int = 1, page_size: int = 20) -> dict:
    """分页查询抑制规则"""
    pagination = AlertSuppression.query.order_by(
        AlertSuppression.created_at.desc()
    ).paginate(page=page, per_page=page_size, error_out=False)

    return {
        "items": [r.to_dict() for r in pagination.items],
        "page": page,
        "page_size": page_size,
        "total": pagination.total,
    }


def create_suppression(data: dict) -> AlertSuppression:
    """创建抑制规则"""
    rule = AlertSuppression(
        rule_name=data.get("rule_name", ""),
        match_type=data.get("match_type", "ip"),
        match_value=data.get("match_value", ""),
        reason=data.get("reason", ""),
        expires_at=_parse_expires(data.get("expires_in_hours")),
        created_by=data.get("created_by", ""),
        is_active=1,
    )
    db.session.add(rule)
    db.session.commit()
    invalidate_cache()
    return rule


def _parse_expires(hours):
    if hours and int(hours) > 0:
        from datetime import timedelta
        return datetime.now(timezone.utc) + timedelta(hours=int(hours))
    return None


def update_suppression(rule_id: int, data: dict) -> AlertSuppression | None:
    """更新抑制规则"""
    rule = db.session.get(AlertSuppression, rule_id)
    if not rule:
        return None

    if "rule_name" in data:
        rule.rule_name = data["rule_name"]
    if "match_type" in data:
        rule.match_type = data["match_type"]
    if "match_value" in data:
        rule.match_value = data["match_value"]
    if "reason" in data:
        rule.reason = data["reason"]
    if "is_active" in data:
        rule.is_active = 1 if data["is_active"] else 0
    if "expires_in_hours" in data:
        rule.expires_at = _parse_expires(data["expires_in_hours"])

    db.session.commit()
    invalidate_cache()
    return rule


def delete_suppression(rule_id: int) -> bool:
    """删除抑制规则"""
    rule = db.session.get(AlertSuppression, rule_id)
    if not rule:
        return False
    db.session.delete(rule)
    db.session.commit()
    invalidate_cache()
    return True


def toggle_suppression(rule_id: int) -> AlertSuppression | None:
    """切换抑制规则启用状态"""
    rule = db.session.get(AlertSuppression, rule_id)
    if not rule:
        return None
    rule.is_active = 0 if rule.is_active else 1
    db.session.commit()
    invalidate_cache()
    return rule
