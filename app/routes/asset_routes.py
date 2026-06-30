"""资产关联 API"""
from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.services.asset_service import (
    discover_assets, build_relations, list_assets,
    get_asset_detail, get_asset_topology, correlate_with_chain,
)

asset_bp = Blueprint("assets", __name__)


@asset_bp.route("", methods=["GET"])
@login_required
def list_assets_api():
    """获取资产列表"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    asset_type = request.args.get("asset_type")
    keyword = request.args.get("keyword")
    sort_by = request.args.get("sort_by", "risk_score")

    result = list_assets(
        page=page, page_size=page_size,
        asset_type=asset_type, keyword=keyword, sort_by=sort_by,
    )
    return jsonify({"code": 0, "data": result})


@asset_bp.route("/discover", methods=["POST"])
@login_required
def discover_assets_api():
    """从日志/告警中发现资产"""
    result = discover_assets()
    return jsonify({"code": 0, "data": result})


@asset_bp.route("/relations", methods=["POST"])
@login_required
def build_relations_api():
    """构建资产关联关系"""
    src_ip = request.json.get("src_ip") if request.is_json else None
    # 默认 None = 查全部历史告警(资产关联是累积的)
    time_window = request.json.get("time_window_minutes") if request.is_json else None
    result = build_relations(src_ip=src_ip, time_window_minutes=time_window)
    return jsonify({"code": 0, "data": result})


@asset_bp.route("/topology", methods=["GET"])
@login_required
def get_topology_api():
    """获取资产拓扑"""
    topology = get_asset_topology()
    return jsonify({"code": 0, "data": topology})


@asset_bp.route("/<int:asset_id>", methods=["GET"])
@login_required
def get_asset_api(asset_id: int):
    """获取资产详情"""
    detail = get_asset_detail(asset_id)
    if not detail:
        return jsonify({"code": 404, "message": "资产不存在"}), 404
    return jsonify({"code": 0, "data": detail})


@asset_bp.route("/chain/<int:chain_id>", methods=["GET"])
@login_required
def correlate_chain_api(chain_id: int):
    """获取攻击链关联的资产"""
    result = correlate_with_chain(chain_id)
    return jsonify({"code": 0, "data": result})
