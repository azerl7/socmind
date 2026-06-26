"""系统配置接口"""
from flask import Blueprint, request, jsonify
from app import db
from app.models.config import SystemConfig
from app.utils.response import success_response, error_response

config_bp = Blueprint("config_routes", __name__)


@config_bp.route("", methods=["GET"])
def list_configs():
    configs = SystemConfig.query.all()
    return jsonify(success_response([c.to_dict() for c in configs]))


@config_bp.route("/<config_key>", methods=["PUT"])
def update_config(config_key):
    config = SystemConfig.query.filter_by(config_key=config_key).first()
    if not config:
        return jsonify(error_response(40401, "配置项不存在")), 404

    data = request.get_json() or {}
    if "config_value" in data:
        config.config_value = data["config_value"]
        db.session.commit()

    return jsonify(success_response(config.to_dict()))
