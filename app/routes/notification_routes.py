"""通知接口：告警通知触发、通知测试"""
from flask import Blueprint, request, jsonify
from app import db
from app.models.alert import Alert
from app.services.notification_service import notify_alert, test_notification
from app.utils.response import success_response, error_response

notification_bp = Blueprint("notification_routes", __name__)


@notification_bp.route("/test", methods=["POST"])
def test():
    """发送测试通知"""
    data = request.get_json() or {}
    channel = data.get("channel", "webhook")
    result = test_notification(channel)
    if result.get("success"):
        return jsonify(success_response({"message": result["message"]}))
    return jsonify(error_response(50001, result.get("message", "通知发送失败"))), 500


@notification_bp.route("/alert/<int:alert_id>", methods=["POST"])
def notify(alert_id):
    """对指定告警发送通知"""
    force = request.get_json() or {}
    result = notify_alert(alert_id, force=force.get("force", False))
    return jsonify(success_response(result))
