"""全局搜索 API"""
from flask import Blueprint, request, jsonify
from flask_login import login_required

from app.services.search_service import global_search
from app.utils.response import success_response

search_bp = Blueprint("search", __name__)


@search_bp.route("", methods=["GET"])
@login_required
def search():
    """全局搜索"""
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify(success_response({
            "alerts": {"items": [], "total": 0},
            "logs": {"items": [], "total": 0},
            "assets": {"items": [], "total": 0},
            "chains": {"items": [], "total": 0},
        }))

    results = global_search(q)
    return jsonify(success_response(results))
