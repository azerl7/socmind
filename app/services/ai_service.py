"""AI 研判服务：OpenAI API 调用、Prompt 模板、降级机制"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app import db
from app.models.alert import Alert, AlertEvidence
from app.models.ai_analysis import AIAnalysis
from app.models.attack_chain import AttackChain, AttackChainNode
from app.models.config import SystemConfig, AICallLog
from app.models.knowledge import KnowledgeDoc
from app.utils.security import generate_alert_no

logger = logging.getLogger(__name__)


def _get_openai_config() -> dict:
    """从系统配置表获取 OpenAI 配置"""
    configs = {c.config_key: c.config_value for c in SystemConfig.query.all()}
    return {
        "api_key": configs.get("openai_api_key", ""),
        "model": configs.get("openai_model", "gpt-4o-mini"),
        "base_url": configs.get("openai_base_url", ""),
    }


def _call_openai(prompt: str, system_prompt: str = "") -> dict:
    """调用 OpenAI API

    Returns:
        {"success": bool, "content": str, "error": str}
    """
    cfg = _get_openai_config()
    if not cfg["api_key"]:
        return {"success": False, "content": "", "error": "OpenAI API Key 未配置"}

    try:
        from openai import OpenAI

        client_kwargs = {"api_key": cfg["api_key"]}
        if cfg["base_url"]:
            client_kwargs["base_url"] = cfg["base_url"]

        client = OpenAI(**client_kwargs)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        completion = client.chat.completions.create(
            model=cfg["model"],
            messages=messages,
            temperature=0.3,
            max_tokens=2000,
        )

        content = completion.choices[0].message.content or ""

        # 提取 JSON（如果被 markdown 代码块包裹）
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[-1]
            if "```" in content:
                content = content.rsplit("```", 1)[0]
            content = content.strip()

        tokens_in = completion.usage.prompt_tokens if completion.usage else 0
        tokens_out = completion.usage.completion_tokens if completion.usage else 0

        return {
            "success": True,
            "content": content,
            "error": "",
            "prompt_tokens": tokens_in,
            "completion_tokens": tokens_out,
            "total_tokens": tokens_in + tokens_out,
        }

    except Exception as e:
        logger.error(f"OpenAI API 调用失败: {e}")
        return {"success": False, "content": "", "error": str(e)}


def _log_ai_call(target_type: str, target_id: int, model: str,
                  status: str, tokens: int = 0, error: str = ""):
    """记录 AI 调用日志"""
    log = AICallLog(
        target_type=target_type,
        target_id=target_id,
        model_name=model,
        status=status,
        total_tokens=tokens,
        error_message=error[:500] if error else None,
    )
    db.session.add(log)
    db.session.commit()


# ── Prompt 模板 ──

def _build_single_alert_prompt(alert: Alert, rag_knowledge: str = "") -> str:
    """构建单告警研判 Prompt"""
    rule_info = ""
    if alert.rule:
        rule_info = f"规则: {alert.rule.rule_code} - {alert.rule.rule_name}"
        if alert.rule.description:
            rule_info += f"\n描述: {alert.rule.description}"

    raw_log = alert.raw_log.raw_content if alert.raw_log else ""

    # 上下文日志
    context_logs = ""
    if alert.src_ip:
        from app.models.log import RawLog
        related = RawLog.query.filter(
            RawLog.src_ip == alert.src_ip,
            RawLog.log_type == alert.raw_log.log_type if alert.raw_log else True,
        ).order_by(RawLog.event_time.desc()).limit(5).all()
        if related:
            context_logs = "\n".join(f"[{r.event_time}] {r.src_ip} {r.url or r.action or ''}" for r in related)

    prompt = f"""你是一名企业安全运营中心 SOC 分析员。请基于以下结构化告警信息进行安全研判。

【告警信息】
- 告警标题：{alert.title or ''}
- 攻击类型：{alert.attack_type or ''}
- 严重等级：{alert.severity or ''}
- 风险分：{alert.risk_score or 0}
- 源 IP：{alert.src_ip or ''}
- 目标资产：{alert.dst_ip or alert.asset or ''}
- 发生时间：{alert.event_time.isoformat() if alert.event_time else ''}

【命中规则】
{rule_info}

【原始日志】
{raw_log[:2000] if raw_log else '无'}

【上下文日志】
{context_logs[:2000] if context_logs else '无'}

【安全知识】
{rag_knowledge[:2000] if rag_knowledge else '无'}

请输出以下 JSON 结构（只输出 JSON，不要其他内容）：
{{
  "summary": "事件摘要",
  "attack_type": "攻击类型判断",
  "risk_level": "low/medium/high/critical",
  "attack_stage": "攻击阶段",
  "evidence": ["证据1", "证据2"],
  "impact": "可能影响范围",
  "false_positive_possibility": "low/medium/high",
  "suggestion": "处置建议",
  "management_summary": "管理层摘要",
  "technical_steps": ["处置步骤1", "处置步骤2"]
}}"""
    return prompt


def _build_chain_prompt(chain: AttackChain) -> str:
    """构建攻击链分析 Prompt"""
    nodes = AttackChainNode.query.filter_by(chain_id=chain.id).order_by(AttackChainNode.sort_order).all()
    chain_text = "\n".join(
        f"[{n.event_time}] 阶段: {n.stage_code} - {n.node_title}\n{n.evidence or ''}"
        for n in nodes
    )

    prompt = f"""你是一名高级安全事件响应分析师。请根据以下攻击链节点和证据，还原攻击过程并给出处置建议。

【攻击链节点】
{chain_text}

请输出以下内容：
1. 事件总体摘要。
2. 攻击阶段还原。
3. 每个阶段的关键证据。
4. 攻击成功可能性判断。
5. 影响范围分析。
6. 处置优先级。
7. 技术处置步骤。
8. 管理层摘要。
9. 后续加固建议。"""
    return prompt


# ── 研判执行 ──

def analyze_alert(alert_id: int, use_rag: bool = True, include_context: bool = True) -> dict:
    """对单条告警执行 AI 研判

    Returns:
        研判结果字典 (或降级结果)
    """
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return {"error": "告警不存在", "code": 40401}

    cfg = _get_openai_config()

    # 检索 RAG 知识
    rag_knowledge = ""
    if use_rag:
        from app.services.rag_service import search_knowledge
        rag_knowledge = search_knowledge(alert.attack_type)

    # 构建 Prompt
    prompt = _build_single_alert_prompt(alert, rag_knowledge)

    # 调用 OpenAI
    result = _call_openai(prompt)

    analysis_id = None

    if result["success"]:
        # 解析 JSON 结果
        parsed = _parse_json_result(result["content"])
        status = "success"

        analysis = AIAnalysis(
            target_type="alert",
            target_id=alert_id,
            model_name=cfg.get("model", "gpt-4o-mini"),
            prompt=prompt[:5000],
            result_json=parsed,
            summary=parsed.get("summary", ""),
            risk_level=parsed.get("risk_level", alert.severity),
            suggestion=parsed.get("suggestion", ""),
            status=status,
        )
        db.session.add(analysis)
        db.session.flush()
        analysis_id = analysis.id
        db.session.commit()

        _log_ai_call("alert", alert_id, cfg.get("model", ""), "success",
                     result.get("total_tokens", 0))

        return {
            "analysis_id": analysis_id,
            "summary": parsed.get("summary", "AI 研判完成"),
            "risk_level": parsed.get("risk_level", alert.severity),
            "attack_stage": parsed.get("attack_stage", ""),
            "suggestion": parsed.get("suggestion", ""),
            "false_positive_possibility": parsed.get("false_positive_possibility", "medium"),
            "management_summary": parsed.get("management_summary", ""),
            "technical_steps": parsed.get("technical_steps", []),
            "evidence": parsed.get("evidence", []),
            "impact": parsed.get("impact", ""),
        }

    # API 失败 → 降级
    return _fallback_analysis(alert, error=result["error"])


def _fallback_analysis(alert: Alert, error: str = "") -> dict:
    """AI 调用失败时的降级研判结果"""
    severity_scores = {"low": 20, "medium": 50, "high": 75, "critical": 95}

    analysis = AIAnalysis(
        target_type="alert",
        target_id=alert.id,
        status="fallback",
        error_message=error,
        summary=f"[降级研判] 基于规则引擎结果：检测到 {alert.attack_type} 行为",
        risk_level=alert.severity,
        suggestion="1. 查看原始日志确认攻击行为\n2. 检查受影响系统\n3. 根据安全策略采取相应处置措施",
    )
    db.session.add(analysis)
    db.session.commit()

    risk_score = alert.risk_score or severity_scores.get(alert.severity, 50)

    return {
        "analysis_id": analysis.id,
        "summary": f"[降级研判] 规则引擎检测到 {alert.attack_type}，风险分 {risk_score}。AI 服务不可用，请自行分析。",
        "risk_level": alert.severity,
        "attack_stage": alert.rule.stage_code if alert.rule else "",
        "suggestion": "AI 服务暂不可用，建议手动查看原始日志和规则信息进行研判",
        "false_positive_possibility": "medium",
        "management_summary": f"系统检测到 {alert.attack_type} 告警（{alert.severity}级），AI 深度分析暂不可用，建议安全团队关注。",
        "technical_steps": [
            f"查看告警 #{alert.id} 的原始日志",
            "确认攻击 Payload 和影响范围",
            "根据安全策略进行处置",
            "后续配置 OpenAI API 后可获得 AI 辅助研判",
        ],
        "_fallback": True,
        "_error": error,
    }


def analyze_chain(chain_id: int) -> dict:
    """对攻击链执行 AI 分析"""
    chain = db.session.get(AttackChain, chain_id)
    if not chain:
        return {"error": "攻击链不存在", "code": 40401}

    cfg = _get_openai_config()
    prompt = _build_chain_prompt(chain)
    result = _call_openai(prompt)

    if result["success"]:
        analysis = AIAnalysis(
            target_type="chain",
            target_id=chain_id,
            model_name=cfg.get("model", ""),
            prompt=prompt[:5000],
            summary=result["content"][:1000],
            status="success",
        )
        db.session.add(analysis)
        db.session.commit()

        # 更新攻击链 AI 摘要
        chain.ai_summary = result["content"][:2000]
        db.session.commit()

        return {
            "analysis_id": analysis.id,
            "summary": result["content"][:500],
            "suggestion": "",
        }

    return {
        "analysis_id": None,
        "summary": "AI 分析暂不可用，请检查 API 配置",
        "suggestion": "AI 服务暂不可用",
    }


def _parse_json_result(content: str) -> dict:
    """尝试解析 AI 返回的 JSON 内容"""
    content = content.strip()
    # 尝试直接解析
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # 尝试提取 JSON 块
    import re
    m = re.search(r'\{.*\}', content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    # 返回原始文本
    return {"raw_text": content[:2000]}
