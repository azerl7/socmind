"""AI 研判接口 — 接入 ai_service + rag_service"""
from flask import Blueprint, request, jsonify
from app import db
from app.models.ai_analysis import AIAnalysis
from app.services.ai_service import analyze_alert, analyze_chain
from app.utils.response import success_response, error_response, paginated_response
from flask_login import login_required, current_user

ai_bp = Blueprint("ai_routes", __name__)


@ai_bp.route("/analyze/alert/<int:alert_id>", methods=["POST"])
def analyze_alert_endpoint(alert_id):
    """对单条告警执行 AI 研判"""
    data = request.get_json() or {}
    use_rag = data.get("use_rag", True)
    include_context = data.get("include_context", True)

    result = analyze_alert(alert_id, use_rag=use_rag, include_context=include_context)
    if "error" in result:
        code = result.get("code", 50001)
        return jsonify(error_response(code, result["error"])), (404 if code == 40401 else 500)

    return jsonify(success_response(result))


@ai_bp.route("/analyze/chain/<int:chain_id>", methods=["POST"])
def analyze_chain_endpoint(chain_id):
    """对攻击链执行 AI 分析"""
    result = analyze_chain(chain_id)
    if "error" in result:
        return jsonify(error_response(40401, result["error"])), 404
    return jsonify(success_response(result))


@ai_bp.route("/analyses", methods=["GET"])
def list_analyses():
    """查询 AI 研判历史"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    target_type = request.args.get("target_type")
    target_id = request.args.get("target_id", type=int)
    status = request.args.get("status")

    query = AIAnalysis.query
    if target_type:
        query = query.filter_by(target_type=target_type)
    if target_id:
        query = query.filter_by(target_id=target_id)
    if status:
        query = query.filter_by(status=status)

    pagination = query.order_by(AIAnalysis.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify(paginated_response(
        [a.to_dict() for a in pagination.items],
        page, page_size, pagination.total
    ))


@ai_bp.route("/analyses/<int:analysis_id>", methods=["GET"])
def get_analysis(analysis_id):
    """查询单条 AI 研判详情"""
    analysis = db.session.get(AIAnalysis, analysis_id)
    if not analysis:
        return jsonify(error_response(40401, "研判记录不存在")), 404
    return jsonify(success_response(analysis.to_dict()))


@ai_bp.route("/analyses/<int:analysis_id>/revise", methods=["PUT"])
def revise_analysis(analysis_id):
    """AI-08: 人工修订 AI 研判结果"""
    analysis = db.session.get(AIAnalysis, analysis_id)
    if not analysis:
        return jsonify(error_response(40401, "研判记录不存在")), 404

    data = request.get_json() or {}
    if not data:
        return jsonify(error_response(40001, "请提供修订内容")), 400

    # 保存旧记录到 result_json 中
    old_data = {
        "summary": analysis.summary,
        "risk_level": analysis.risk_level,
        "suggestion": analysis.suggestion,
        "result_json": analysis.result_json,
    }

    # 更新字段
    if "summary" in data:
        analysis.summary = data["summary"]
    if "risk_level" in data:
        analysis.risk_level = data["risk_level"]
    if "suggestion" in data:
        analysis.suggestion = data["suggestion"]
    if "result_json" in data:
        analysis.result_json = {"revised_from": old_data.get("result_json"), "user_edited": data["result_json"]}
    if "revision_comment" in data:
        analysis.revision_comment = data["revision_comment"]

    from datetime import datetime, timezone
    analysis.is_revised = True
    analysis.revised_at = datetime.now(timezone.utc)

    from flask_login import current_user
    try:
        analysis.revised_by = current_user.id
        analysis.revised_by_name = current_user.username
    except Exception:
        analysis.revised_by = 0
        analysis.revised_by_name = "unknown"

    db.session.commit()
    return jsonify(success_response(analysis.to_dict()))


@ai_bp.route("/test", methods=["POST"])
def test_provider():
    """测试当前 provider 是否可连接"""
    from app.services.ai_service import _get_provider_config, _call_llm

    cfg = _get_provider_config()
    if not cfg["api_key"]:
        return jsonify(error_response(
            40001,
            f"{cfg['provider_name']} API Key 未配置,请先在系统配置页填写"
        )), 400

    # 用最小 prompt 测试连接
    result = _call_llm("回复一个字:OK", system_prompt="")
    if result.get("success"):
        return jsonify(success_response({
            "provider": cfg["provider"],
            "provider_name": cfg["provider_name"],
            "model": cfg["model"],
            "base_url": cfg["base_url"],
            "response": result.get("content", "")[:200],
            "tokens_used": result.get("total_tokens", 0),
        }))

    return jsonify(error_response(
        50001,
        f"{cfg['provider_name']} 调用失败: {result.get('error', '未知错误')}"
    )), 500
    