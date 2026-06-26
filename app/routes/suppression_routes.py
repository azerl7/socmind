"""告警抑制规则 API"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from app.services.suppression_service import (
    list_suppressions, create_suppression, update_suppression,
    delete_suppression, toggle_suppression,
)
from app.utils.response import success_response, error_response

suppression_bp = Blueprint("suppressions", __name__)


@suppression_bp.route("", methods=["GET"])
@login_required
def list_rules():
    """获取抑制规则列表"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    result = list_suppressions(page=page, page_size=page_size)
    return jsonify(success_response(result))


@suppression_bp.route("", methods=["POST"])
@login_required
def create_rule():
    """创建抑制规则"""
    data = request.get_json() or {}
    required = ["rule_name", "match_type", "match_value"]
    for field in required:
        if not data.get(field):
            return jsonify(error_response(40001, f"{field} 必填")), 400

    data["created_by"] = current_user.username
    rule = create_suppression(data)
    return jsonify(success_response(rule.to_dict()), 201)


@suppression_bp.route("/<int:rule_id>", methods=["PUT"])
@login_required
def update_rule(rule_id: int):
    """更新抑制规则"""
    data = request.get_json() or {}
    rule = update_suppression(rule_id, data)
    if not rule:
        return jsonify(error_response(404, "规则不存在")), 404
    return jsonify(success_response(rule.to_dict()))


@suppression_bp.route("/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle_rule(rule_id: int):
    """切换规则状态"""
    rule = toggle_suppression(rule_id)
    if not rule:
        return jsonify(error_response(404, "规则不存在")), 404
    return jsonify(success_response(rule.to_dict()))


@suppression_bp.route("/<int:rule_id>", methods=["DELETE"])
@login_required
def delete_rule(rule_id: int):
    """删除抑制规则"""
    ok = delete_suppression(rule_id)
    if not ok:
        return jsonify(error_response(404, "规则不存在")), 404
    return jsonify(success_response({"deleted": True}))
