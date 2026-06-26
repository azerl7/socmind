"""数据导出服务：CSV / JSON / 报告导出"""
import csv
import json
import io
from datetime import datetime, timezone
from typing import List

from app import db
from app.models.alert import Alert, AlertEvidence
from app.models.log import RawLog
from app.models.attack_chain import AttackChain, AttackChainNode


def export_alerts_csv(
    severity: str | None = None,
    status: str | None = None,
    attack_type: str | None = None,
    src_ip: str | None = None,
    limit: int = 5000,
) -> str:
    """导出告警列表为 CSV 格式"""
    query = Alert.query.order_by(Alert.event_time.desc())
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if attack_type:
        query = query.filter(Alert.attack_type == attack_type)
    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)

    alerts = query.limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["告警编号", "标题", "攻击类型", "严重等级", "风险分",
                     "源IP", "目标IP", "用户名", "状态", "时间"])

    for a in alerts:
        writer.writerow([
            a.alert_no,
            a.title,
            a.attack_type,
            a.severity,
            a.risk_score,
            a.src_ip or "",
            a.dst_ip or "",
            a.username or "",
            a.status,
            a.event_time.strftime("%Y-%m-%d %H:%M:%S") if a.event_time else "",
        ])

    return output.getvalue()


def export_alerts_json(
    severity: str | None = None,
    status: str | None = None,
    attack_type: str | None = None,
    src_ip: str | None = None,
    limit: int = 5000,
) -> str:
    """导出告警列表为 JSON 格式"""
    query = Alert.query.order_by(Alert.event_time.desc())
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if attack_type:
        query = query.filter(Alert.attack_type == attack_type)
    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)

    alerts = query.limit(limit).all()

    # 包含证据信息
    result = []
    for a in alerts:
        evidence = AlertEvidence.query.filter_by(alert_id=a.id).all()
        result.append({
            "alert_no": a.alert_no,
            "title": a.title,
            "attack_type": a.attack_type,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "username": a.username,
            "status": a.status,
            "event_time": a.event_time.isoformat() if a.event_time else None,
            "evidence": [{"type": e.evidence_type, "title": e.title, "content": e.content}
                         for e in evidence],
        })

    return json.dumps(result, ensure_ascii=False, indent=2)


def export_logs_csv(
    log_type: str | None = None,
    src_ip: str | None = None,
    keyword: str | None = None,
    limit: int = 5000,
) -> str:
    """导出日志为 CSV 格式"""
    query = RawLog.query.order_by(RawLog.event_time.desc())
    if log_type:
        query = query.filter(RawLog.log_type == log_type)
    if src_ip:
        query = query.filter(RawLog.src_ip == src_ip)
    if keyword:
        query = query.filter(RawLog.raw_content.ilike(f"%{keyword}%"))

    logs = query.limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "类型", "时间", "源IP", "方法", "URL", "状态码", "账号", "来源"])

    for log in logs:
        writer.writerow([
            log.id,
            log.log_type,
            log.event_time.strftime("%Y-%m-%d %H:%M:%S") if log.event_time else "",
            log.src_ip or "",
            log.http_method or "",
            log.url or "",
            log.status_code or "",
            log.username or "",
            log.source or "",
        ])

    return output.getvalue()


def export_chains_csv(limit: int = 500) -> str:
    """导出攻击链为 CSV 格式"""
    chains = AttackChain.query.order_by(AttackChain.created_at.desc()).limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["链编号", "标题", "源IP", "目标资产", "阶段数",
                     "可信度", "风险分", "开始时间", "结束时间", "创建时间"])

    for c in chains:
        writer.writerow([
            c.chain_no,
            c.title,
            c.src_ip or "",
            c.target_asset or "",
            c.stage_count,
            c.confidence,
            c.risk_score,
            c.start_time.strftime("%Y-%m-%d %H:%M:%S") if c.start_time else "",
            c.end_time.strftime("%Y-%m-%d %H:%M:%S") if c.end_time else "",
            c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else "",
        ])

    return output.getvalue()


def export_chain_detail_json(chain_id: int) -> str | None:
    """导出攻击链详情为 JSON"""
    chain = db.session.get(AttackChain, chain_id)
    if not chain:
        return None

    nodes = AttackChainNode.query.filter_by(chain_id=chain_id).order_by(AttackChainNode.sort_order).all()

    result = chain.to_detail_dict()
    result["nodes"] = [n.to_dict() for n in nodes]

    # 关联告警详情
    from app.models.alert import Alert
    alert_ids = [n.alert_id for n in nodes if n.alert_id]
    alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all() if alert_ids else []
    result["alerts"] = [a.to_dict() for a in alerts]

    return json.dumps(result, ensure_ascii=False, indent=2)
