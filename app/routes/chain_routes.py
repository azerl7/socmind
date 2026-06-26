"""攻击链接口 — 接入 attack_chain_service + ai_service"""
from flask import Blueprint, request, jsonify
from app import db
from app.models.attack_chain import AttackChain
from app.services.attack_chain_service import (
    generate_attack_chain, get_attack_chain_detail, list_attack_chains,
)
from app.services.ai_service import analyze_chain
from app.utils.response import success_response, error_response, paginated_response
from flask_login import login_required

chain_bp = Blueprint("chain_routes", __name__)


@chain_bp.route("/generate", methods=["POST"])
def generate():
    data = request.get_json() or {}
    result = generate_attack_chain(
        src_ip=data.get("src_ip"), asset=data.get("asset"),
        start_time=data.get("start_time"), end_time=data.get("end_time"),
        event_id=data.get("event_id"),
    )
    return jsonify(success_response(result))


@chain_bp.route("", methods=["GET"])
def list_chains():
    page = request.args.get("page", 1, type=int)
    result = list_attack_chains(page=page, page_size=20)
    return jsonify(paginated_response(result["items"], page, 20, result["total"]))


@chain_bp.route("/<int:chain_id>", methods=["GET"])
def get_chain(chain_id):
    detail = get_attack_chain_detail(chain_id)
    if not detail:
        return jsonify(error_response(40401, "攻击链不存在")), 404
    return jsonify(success_response(detail))


@chain_bp.route("/<int:chain_id>/ai-summary", methods=["POST"])
def ai_summary(chain_id):
    result = analyze_chain(chain_id)
    if "error" in result:
        return jsonify(error_response(50001, result["error"])), 500
    return jsonify(success_response(result))


@chain_bp.route("/<int:chain_id>/nodes", methods=["POST"])
@login_required
def add_node(chain_id):
    from app.models.attack_chain import AttackChainNode, AttackStage
    chain = db.session.get(AttackChain, chain_id)
    if not chain:
        return jsonify(error_response(40401, "攻击链不存在")), 404
    data = request.get_json() or {}
    if not data.get("stage_code"):
        return jsonify(error_response(40001, "请指定攻击阶段")), 400
    stage = AttackStage.query.filter_by(stage_code=data["stage_code"]).first()
    title = f"{stage.stage_name} - {data.get('node_title', '手动节点')}" if stage else data.get('node_title', '手动节点')
    max_order = db.session.query(db.func.max(AttackChainNode.sort_order)).filter_by(chain_id=chain_id).scalar() or 0
    node = AttackChainNode(
        chain_id=chain.id, stage_code=data["stage_code"], node_title=title,
        node_desc=data.get("node_desc", ""), evidence=data.get("evidence", ""),
        alert_id=data.get("alert_id"), raw_log_id=data.get("raw_log_id"),
        sort_order=max_order + 1,
    )
    db.session.add(node)
    db.session.commit()
    return jsonify(success_response(node.to_dict()), 201)


@chain_bp.route("/nodes/<int:node_id>", methods=["PUT"])
@login_required
def update_node(node_id):
    from app.models.attack_chain import AttackChainNode
    node = db.session.get(AttackChainNode, node_id)
    if not node:
        return jsonify(error_response(40401, "节点不存在")), 404
    for field in ["node_title", "node_desc", "evidence", "stage_code"]:
        if field in request.get_json():
            setattr(node, field, request.get_json()[field])
    db.session.commit()
    return jsonify(success_response(node.to_dict()))


@chain_bp.route("/nodes/<int:node_id>", methods=["DELETE"])
@login_required
def delete_node(node_id):
    from app.models.attack_chain import AttackChainNode
    node = db.session.get(AttackChainNode, node_id)
    if not node:
        return jsonify(error_response(40401, "节点不存在")), 404
    db.session.delete(node)
    db.session.commit()
    return jsonify(success_response({"deleted": True}))


@chain_bp.route("/nodes/reorder", methods=["POST"])
@login_required
def reorder_nodes():
    from app.models.attack_chain import AttackChainNode
    node_ids = (request.get_json() or {}).get("node_ids", [])
    for order, nid in enumerate(node_ids, 1):
        AttackChainNode.query.filter_by(id=nid).update({"sort_order": order})
    db.session.commit()
    return jsonify(success_response({"reordered": len(node_ids)}))
