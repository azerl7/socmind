"""定时任务管理 API"""
from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.services.scheduler_service import (
    get_scheduler_status, add_scheduled_job, remove_scheduled_job,
)
from app.utils.response import success_response, error_response

scheduler_bp = Blueprint("scheduler", __name__)


@scheduler_bp.route("/status", methods=["GET"])
@login_required
def status():
    """获取调度器状态"""
    status = get_scheduler_status()
    return jsonify(success_response(status))


@scheduler_bp.route("/jobs", methods=["POST"])
@login_required
def add_job():
    """添加定时任务"""
    data = request.get_json() or {}
    job_id = data.get("job_id", "")
    cron_expr = data.get("cron_expression", "")
    job_name = data.get("job_name", "")

    if not job_id or not cron_expr:
        return jsonify(error_response(40001, "job_id 和 cron_expression 必填")), 400

    ok = add_scheduled_job(job_id, cron_expr, job_name)
    if ok:
        return jsonify(success_response({"job_id": job_id, "cron": cron_expr}))
    else:
        return jsonify(error_response(40002, f"不支持的任务类型: {job_id}")), 400


@scheduler_bp.route("/jobs/<job_id>", methods=["DELETE"])
@login_required
def remove_job(job_id: str):
    """移除定时任务"""
    ok = remove_scheduled_job(job_id)
    if ok:
        return jsonify(success_response({"job_id": job_id}))
    else:
        return jsonify(error_response(404, f"任务不存在: {job_id}")), 404
