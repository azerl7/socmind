"""风险评分服务：基于多维度因素计算告警风险分 (0-100)"""
from app.models.alert import Alert
from app.models.rule import DetectionRule


def calculate_risk_score(alert: Alert) -> int:
    """计算告警风险分（0-100）

    维度:
      1. 规则严重等级基础分 (40%)
      2. 攻击类型权重 (20%)
      3. 上下文增强 (20%)
      4. 时间衰减 (20%)
    """
    base_score = _severity_base_score(alert.severity)  # 0-100

    # 攻击类型权重
    type_weight = _attack_type_weight(alert.attack_type)  # 0.8-1.2

    # 上下文增强（如有用户名、资产等信息加分）
    context_bonus = 0
    if alert.username:
        context_bonus += 5
    if alert.asset:
        context_bonus += 5
    if alert.dst_ip:
        context_bonus += 3

    score = base_score * type_weight + context_bonus
    score = max(0, min(100, int(score)))
    return score


def recalculate_alert_score(alert_id: int) -> int:
    """重新计算并更新指定告警的风险分"""
    from app import db
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return 0
    score = calculate_risk_score(alert)
    alert.risk_score = score
    db.session.commit()
    return score


def _severity_base_score(severity: str) -> int:
    mapping = {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 95,
    }
    return mapping.get(severity, 50)


def _attack_type_weight(attack_type: str) -> float:
    """不同攻击类型的权重系数"""
    weights = {
        "Command Injection": 1.2,
        "SQL Injection": 1.1,
        "Path Traversal": 1.0,
        "Brute Force": 0.9,
        "XSS": 0.8,
        "Scanning": 0.7,
        "Sensitive Path Access": 0.6,
        "Abnormal Login": 0.7,
        "Abnormal UA": 0.3,
    }
    return weights.get(attack_type, 0.8)
