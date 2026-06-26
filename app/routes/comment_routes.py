"""告警评论 API"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from app.services.comment_service import add_comment, get_comments, delete_comment
from app.utils.response import success_response, error_response

comment_bp = Blueprint("comments", __name__)


@comment_bp.route("/<int:alert_id>", methods=["GET"])
@login_required
def list_comments(alert_id: int):
    """获取告警评论列表"""
    comments = get_comments(alert_id)
    return jsonify(success_response({"items": comments, "total": len(comments)}))


@comment_bp.route("/<int:alert_id>", methods=["POST"])
@login_required
def create_comment(alert_id: int):
    """添加评论"""
    data = request.get_json() or {}
    content = data.get("content", "").strip()
    if not content:
        return jsonify(error_response(40001, "评论内容不能为空")), 400

    comment = add_comment(
        alert_id=alert_id,
        user_id=current_user.id,
        username=current_user.username,
        content=content,
        comment_type=data.get("comment_type", "comment"),
    )
    return jsonify(success_response(comment.to_dict()), 201)


@comment_bp.route("/<int:comment_id>", methods=["DELETE"])
@login_required
def remove_comment(comment_id: int):
    """删除评论"""
    ok = delete_comment(comment_id, current_user.id)
    if not ok:
        return jsonify(error_response(404, "评论不存在或无权限删除")), 404
    return jsonify(success_response({"deleted": True}))
