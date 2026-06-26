"""报告生成服务：Markdown/HTML 报告生成、模板管理"""
import os
import json
from datetime import datetime, timezone

from app import db
from app.models.report import Report, ReportTemplate
from app.models.alert import Alert, AlertEvidence
from app.models.attack_chain import AttackChain, AttackChainNode
from app.models.ai_analysis import AIAnalysis
from app.utils.security import generate_report_no


def _markdown_escape(text: str) -> str:
    """转义 Markdown 特殊字符"""
    if not text:
        return ""
    for ch in ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!']:
        text = text.replace(ch, '\\' + ch)
    return text


# ── 单告警报告 ──

def generate_alert_report(alert_id: int, use_ai: bool = False) -> dict:
    """生成单条告警的 Markdown 报告"""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return {"error": "告警不存在", "code": 40401}

    evidences = AlertEvidence.query.filter_by(alert_id=alert_id).all()
    ai_analysis = AIAnalysis.query.filter_by(
        target_type="alert", target_id=alert_id, status="success"
    ).order_by(AIAnalysis.created_at.desc()).first()

    # 构建 Markdown
    md = f"""# 安全告警分析报告

## 基本信息

| 字段 | 值 |
|---|---|
| 告警编号 | {alert.alert_no or ''} |
| 告警标题 | {alert.title or ''} |
| 攻击类型 | {alert.attack_type or ''} |
| 风险等级 | {alert.severity or ''} |
| 风险评分 | {alert.risk_score or 0} |
| 源 IP | {alert.src_ip or ''} |
| 目标地址 | {alert.dst_ip or ''} |
| 关联账号 | {alert.username or ''} |
| 发生时间 | {alert.event_time.strftime('%Y-%m-%d %H:%M:%S') if alert.event_time else ''} |
| 状态 | {alert.status or ''} |
"""

    # 规则信息
    if alert.rule:
        md += f"""
## 命中规则

- **规则编码**: {alert.rule.rule_code or ''}
- **规则名称**: {alert.rule.rule_name or ''}
- **严重等级**: {alert.rule.severity or ''}
"""

    # 证据
    if evidences:
        md += "\n## 证据列表\n\n"
        for ev in evidences:
            md += f"### {ev.title}\n\n{ev.content}\n\n"

    # AI 研判
    if ai_analysis:
        md += f"""
## AI 研判结论

- **研判摘要**: {ai_analysis.summary or ''}
- **风险等级**: {ai_analysis.risk_level or ''}
- **处置建议**: {ai_analysis.suggestion or ''}
"""
    else:
        md += "\n## AI 研判\n\n（未执行 AI 研判）\n"

    md += f"""
## 处置建议

1. 查看原始日志确认攻击行为
2. 根据攻击类型采取相应处置措施
3. 记录处置结果并更新告警状态

---

*报告生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""

    html = _md_to_html(md)

    report = Report(
        report_no=generate_report_no(),
        title=f"告警报告: {alert.title or alert.attack_type}",
        report_type="alert",
        target_id=alert_id,
        content_md=md,
        content_html=html,
    )
    db.session.add(report)
    db.session.commit()

    return {"report_id": report.id, "report_no": report.report_no, "title": report.title}


# ── 攻击链报告 ──

def generate_chain_report(chain_id: int, use_ai_polish: bool = False) -> dict:
    """生成攻击链的 Markdown 报告"""
    chain = db.session.get(AttackChain, chain_id)
    if not chain:
        return {"error": "攻击链不存在", "code": 40401}

    nodes = AttackChainNode.query.filter_by(chain_id=chain_id).order_by(AttackChainNode.sort_order).all()
    ai_analysis = AIAnalysis.query.filter_by(
        target_type="chain", target_id=chain_id, status="success"
    ).order_by(AIAnalysis.created_at.desc()).first()

    # 阶段名称映射
    from app.models.attack_chain import AttackStage
    stages = {s.stage_code: s.stage_name for s in AttackStage.query.all()}

    md = f"""# 攻击链分析报告

## 事件摘要

- **攻击链编号**: {chain.chain_no or ''}
- **标题**: {chain.title or ''}
- **源 IP**: {chain.src_ip or ''}
- **目标资产**: {chain.target_asset or ''}
- **可信度**: {chain.confidence or ''}
- **风险评分**: {chain.risk_score or 0}
- **阶段数量**: {chain.stage_count or 0}
- **时间范围**: {chain.start_time.strftime('%Y-%m-%d %H:%M:%S') if chain.start_time else ''} ~ {chain.end_time.strftime('%Y-%m-%d %H:%M:%S') if chain.end_time else ''}
"""

    if chain.ai_summary:
        md += f"\n## AI 分析摘要\n\n{chain.ai_summary}\n"

    if nodes:
        md += "\n## 攻击链时间线\n\n"
        md += "| 时间 | 阶段 | 描述 | 证据 |\n|---|---|---|---|\n"
        for node in nodes:
            stage_name = stages.get(node.stage_code, node.stage_code)
            t = node.event_time.strftime('%H:%M:%S') if node.event_time else ''
            evidence = (node.evidence or '')[:100].replace('\n', ' ')
            md += f"| {t} | {stage_name} | {node.node_title or ''} | {evidence} |\n"

        md += "\n## 各阶段详细分析\n\n"
        for node in nodes:
            stage_name = stages.get(node.stage_code, node.stage_code)
            md += f"### {stage_name}\n\n"
            md += f"**{node.node_title or ''}**\n\n"
            if node.node_desc:
                md += f"{node.node_desc}\n\n"
            if node.evidence:
                md += f"**证据:**\n\n```\n{node.evidence}\n```\n\n"

    if ai_analysis:
        md += f"\n## AI 研判\n\n{ai_analysis.summary or ''}\n"

    md += f"""
## 处置建议

1. 确认攻击链完整性和真实性
2. 对每个阶段进行分析验证
3. 修复已发现的安全漏洞
4. 加强安全监控和日志审计
5. 持续跟踪同源 IP 行为

---

*报告生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""

    html = _md_to_html(md)

    report = Report(
        report_no=generate_report_no(),
        title=f"攻击链报告: {chain.title}",
        report_type="chain",
        target_id=chain_id,
        content_md=md,
        content_html=html,
    )
    db.session.add(report)
    db.session.commit()

    return {"report_id": report.id, "report_no": report.report_no, "title": report.title}


def _md_to_html(md: str) -> str:
    """简单 Markdown → HTML 转换（用于报告展示）"""
    html = []
    html.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    html.append("<style>")
    html.append("body { font-family: -apple-system, 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; line-height: 1.6; color: #333; }")
    html.append("h1 { border-bottom: 2px solid #e74c3c; padding-bottom: 10px; color: #c0392b; }")
    html.append("h2 { border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }")
    html.append("h3 { margin-top: 20px; }")
    html.append("table { border-collapse: collapse; width: 100%; margin: 10px 0; }")
    html.append("th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }")
    html.append("th { background: #f5f5f5; }")
    html.append("code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }")
    html.append("pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }")
    html.append(".footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #888; }")
    html.append("</style></head><body>")

    in_table = False
    for line in md.split("\n"):
        if line.startswith("# "):
            html.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("| "):
            if not in_table:
                html.append("<table>")
                in_table = True
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if all(c == "---" or c == "-----" for c in cells):
                continue  # 跳过分隔行
            tag = "th" if not in_table or ("|---" in line or "|---|---" in md.split("\n")[md.split("\n").index(line) - 1:]) else "td"
            html.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
        elif line.startswith("---"):
            if in_table:
                html.append("</table>")
                in_table = False
            else:
                html.append("<hr>")
        elif line.startswith("```"):
            html.append("<pre>")
        elif line.startswith("- "):
            html.append(f"<li>{line[2:]}</li>")
        elif line.strip():
            if in_table:
                html.append("</table>")
                in_table = False
            html.append(f"<p>{line}</p>")
        else:
            if in_table:
                html.append("</table>")
                in_table = False

    if in_table:
        html.append("</table>")

    html.append("</body></html>")
    return "\n".join(html)


# ── 报告查询 ──

def get_report(report_id: int) -> dict | None:
    report = db.session.get(Report, report_id)
    if not report:
        return None
    return report.to_dict()


def list_reports(page: int = 1, page_size: int = 20) -> dict:
    """分页查询报告列表"""
    pagination = Report.query.order_by(Report.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return {
        "items": [r.to_dict() for r in pagination.items],
        "page": page,
        "page_size": page_size,
        "total": pagination.total,
    }
