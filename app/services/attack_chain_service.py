"""攻击链生成服务：告警到阶段映射、时间线构建、关联算法"""
from datetime import datetime, timezone
from collections import defaultdict

from app import db
from app.models.alert import Alert, AlertEvent, EventAlertRelation
from app.models.attack_chain import AttackStage, AttackChain, AttackChainNode
from app.utils.security import generate_chain_no


# ── 规则编码 → 攻击阶段映射 ──
RULE_STAGE_MAP = {
    "WEB_SQLI_001": "exploit_attempt",
    "WEB_XSS_001": "exploit_attempt",
    "WEB_PATH_001": "exploit_attempt",
    "WEB_RCE_001": "suspicious_action",
    "ACC_BRUTE_001": "abnormal_login",
    "WEB_SCAN_001": "recon",
    "WEB_SENS_001": "sensitive_path",
    "WEB_UA_001": "recon",
    "ACC_ABNORMAL_001": "abnormal_login",
    "WEB_WEBSHELL_001": "suspicious_action",
    "WEB_SSRF_001": "exploit_attempt",
    "WEB_FILEUPLOAD_001": "exploit_attempt",
    "WEB_LFI_001": "suspicious_action",
    "NET_PORTSCAN_001": "recon",
    # 主机安全规则
    "HOST_SSH_BRUTE_001": "credential_access",
    "HOST_SSH_SUCCESS_001": "initial_access",
    "HOST_SUDO_SENSITIVE_001": "privilege_escalation",
    "HOST_ABNORMAL_TIME_001": "initial_access",
    # 网络安全规则
    "NET_SURICATA_SCAN_001": "recon",
    "NET_SURICATA_ATTACK_001": "exploit_attempt",
    "NET_DNS_C2_001": "suspicious_action",
    "NET_ZEEK_CONN_001": "recon",
}

# 攻击类型 → 攻击阶段映射
ATTACK_TYPE_STAGE_MAP = {
    "SQL Injection": "exploit_attempt",
    "XSS": "exploit_attempt",
    "Path Traversal": "exploit_attempt",
    "Command Injection": "suspicious_action",
    "Brute Force": "abnormal_login",
    "Scanning": "recon",
    "Sensitive Path Access": "sensitive_path",
    "Abnormal UA": "recon",
    "Abnormal Login": "abnormal_login",
    "Webshell Access": "suspicious_action",
    "SSRF": "exploit_attempt",
    "Malicious File Upload": "exploit_attempt",
    "File Inclusion": "suspicious_action",
    "Port Scan": "recon",
    # 主机安全攻击类型
    "SSH Brute Force": "credential_access",
    "SSH Brute Force Success": "initial_access",
    "Suspicious Sudo": "privilege_escalation",
    "Abnormal SSH Login Time": "initial_access",
    # 网络安全攻击类型
    "Network Scan": "recon",
    "Network Web Attack": "exploit_attempt",
    "DNS Suspicious Query": "suspicious_action",
    "Abnormal Connection": "recon",
}


def _map_alert_to_stage(alert: Alert) -> str:
    """将告警映射到攻击阶段"""
    # 先按规则编码映射
    if alert.rule_id:
        from app.models.rule import DetectionRule
        rule = db.session.get(DetectionRule, alert.rule_id)
        if rule:
            if rule.stage_code:
                return rule.stage_code
            stage = RULE_STAGE_MAP.get(rule.rule_code)
            if stage:
                return stage

    # 再按攻击类型映射
    return ATTACK_TYPE_STAGE_MAP.get(alert.attack_type, "unknown")


def generate_attack_chain(
    src_ip: str | None = None,
    asset: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    event_id: int | None = None,
) -> dict:
    """生成攻击链

    通过关联规则将相关告警按时间线组织为攻击链

    Args:
        src_ip: 源 IP 过滤
        asset: 目标资产过滤
        start_time: 时间窗口起始
        end_time: 时间窗口结束
        event_id: 从已有事件生成（如果提供则忽略其他参数）

    Returns:
        {"chain_id": int, "chain_no": str, "stage_count": int, "confidence": str, "risk_score": int}
    """
    # 获取关联告警
    alerts = []

    if event_id:
        # 从事件关联的告警生成
        relations = EventAlertRelation.query.filter_by(event_id=event_id).all()
        alert_ids = [r.alert_id for r in relations]
        alerts = Alert.query.filter(Alert.id.in_(alert_ids)).order_by(Alert.event_time).all()
    else:
        query = Alert.query.filter(
            Alert.status.notin_(["false_positive", "closed"]),
        )
        if src_ip:
            query = query.filter(Alert.src_ip == src_ip)
        if asset:
            query = query.filter(Alert.asset == asset)
        if start_time:
            query = query.filter(Alert.event_time >= start_time)
        if end_time:
            query = query.filter(Alert.event_time <= end_time)

        alerts = query.order_by(Alert.event_time).all()

    if not alerts:
        return {"chain_id": 0, "chain_no": "", "stage_count": 0, "confidence": "low", "risk_score": 0}

    # 为每条告警映射阶段
    stage_alerts = defaultdict(list)
    for alert in alerts:
        stage = _map_alert_to_stage(alert)
        stage_alerts[stage].append(alert)

    # 获取阶段排序
    stages = AttackStage.query.filter_by(framework="web_chain").order_by(AttackStage.stage_order).all()
    stage_order_map = {s.stage_code: s.stage_order for s in stages}
    stage_name_map = {s.stage_code: s.stage_name for s in stages}

    # 排序阶段
    sorted_stages = sorted(stage_alerts.keys(), key=lambda s: stage_order_map.get(s, 99))

    # 计算数据
    all_risk_scores = [a.risk_score for a in alerts if a.risk_score]
    max_risk = max(all_risk_scores) if all_risk_scores else 0
    avg_risk = sum(all_risk_scores) / len(all_risk_scores) if all_risk_scores else 0
    final_risk = int(avg_risk * 0.5 + max_risk * 0.5)

    # 可信度评分
    stage_count = len(sorted_stages)
    if stage_count >= 4:
        confidence = "high"
    elif stage_count >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    # 时间范围
    times = [a.event_time for a in alerts if a.event_time]
    chain_start = min(times) if times else None
    chain_end = max(times) if times else None

    # 创建攻击链
    chain = AttackChain(
        chain_no=generate_chain_no(),
        event_id=event_id,
        title=f"攻击链 - {src_ip or '多源'}",
        src_ip=src_ip or alerts[0].src_ip,
        target_asset=asset or (alerts[0].dst_ip if alerts else ""),
        stage_count=stage_count,
        confidence=confidence,
        risk_score=final_risk,
        start_time=chain_start,
        end_time=chain_end,
    )
    db.session.add(chain)
    db.session.flush()

    # 创建阶段节点
    sort_order = 0
    for stage_code in sorted_stages:
        stage_alerts_list = stage_alerts[stage_code]
        sort_order += 1

        # 合并同一阶段的证据
        evidence_lines = []
        for a in stage_alerts_list:
            evidence_lines.append(f"[{a.event_time.strftime('%H:%M:%S') if a.event_time else ''}] {a.title} (风险:{a.risk_score})")
            if a.src_ip:
                from app.models.alert import AlertEvidence
                ev = AlertEvidence.query.filter_by(alert_id=a.id).first()
                if ev:
                    evidence_lines.append(f"  证据: {ev.content[:200]}")
                    break  # 只取第一条告警的详细证据

        node = AttackChainNode(
            chain_id=chain.id,
            alert_id=stage_alerts_list[0].id,
            raw_log_id=stage_alerts_list[0].raw_log_id,
            stage_code=stage_code,
            node_title=stage_name_map.get(stage_code, stage_code),
            node_desc=f"包含 {len(stage_alerts_list)} 条告警",
            evidence="\n".join(evidence_lines),
            event_time=stage_alerts_list[0].event_time,
            sort_order=sort_order,
        )
        db.session.add(node)

    db.session.commit()

    return {        "chain_id": chain.id,
        "chain_no": chain.chain_no,
        "stage_count": stage_count,
        "confidence": confidence,
        "risk_score": final_risk,
    }


def get_attack_chain_detail(chain_id: int) -> dict | None:
    chain = db.session.get(AttackChain, chain_id)
    if not chain:
        return None
    return chain.to_detail_dict()


def list_attack_chains(page: int = 1, page_size: int = 20) -> dict:
    pagination = AttackChain.query.order_by(AttackChain.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return {
        "items": [c.to_dict() for c in pagination.items],
        "page": page, "page_size": page_size, "total": pagination.total,
    }
