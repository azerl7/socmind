"""日志接口 — 接入 log_parser_service"""
import os
import uuid
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

from app import db
from app.models.log import RawLog, LogImportTask
from app.services.log_parser_service import process_import_task, parse_log_content
from app.utils.response import success_response, error_response, paginated_response
from app.utils.validators import allowed_file, validate_log_type

log_bp = Blueprint("log_routes", __name__)


@log_bp.route("/import", methods=["POST"])
def import_log():
    """上传日志文件并创建导入任务"""
    if "file" not in request.files:
        return jsonify(error_response(40001, "未上传文件")), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify(error_response(40001, "文件为空")), 400

    log_type = request.form.get("log_type", "")
    source = request.form.get("source", "")

    if not validate_log_type(log_type):
        return jsonify(error_response(40002, f"不支持的日志类型: {log_type}")), 400

    if not allowed_file(file.filename):
        return jsonify(error_response(40003, "文件格式不支持")), 400

    # 保存文件
    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    file_path = os.path.join(upload_dir, unique_name)
    file.save(file_path)

    # 创建导入任务
    task = LogImportTask(
        filename=filename,
        file_path=file_path,
        log_type=log_type,
        status="pending",
    )
    db.session.add(task)
    db.session.commit()

    # 自动开始解析
    try:
        result = process_import_task(task.id)
        return jsonify(success_response({
            "task_id": task.id,
            "status": "success",
            "total_count": result["total"],
            "success_count": result["success"],
            "failed_count": result["failed"],
        }))
    except Exception as e:
        task.status = "failed"
        task.error_message = str(e)
        db.session.commit()
        return jsonify(error_response(50001, f"解析失败: {str(e)}")), 500


@log_bp.route("/import/<int:task_id>/parse", methods=["POST"])
def parse_log(task_id):
    """执行日志解析"""
    try:
        result = process_import_task(task_id)
        return jsonify(success_response(result))
    except ValueError as e:
        return jsonify(error_response(40401, str(e))), 404
    except Exception as e:
        return jsonify(error_response(50001, f"解析失败: {str(e)}")), 500


@log_bp.route("/import/<int:task_id>", methods=["GET"])
def get_import_task(task_id):
    """查询导入任务状态"""
    task = db.session.get(LogImportTask, task_id)
    if not task:
        return jsonify(error_response(40401, "导入任务不存在")), 404
    return jsonify(success_response(task.to_dict()))


@log_bp.route("/import", methods=["GET"])
def list_import_tasks():
    """查询导入任务列表"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    pagination = LogImportTask.query.order_by(
        LogImportTask.created_at.desc()
    ).paginate(page=page, per_page=page_size, error_out=False)
    return jsonify(paginated_response(
        [t.to_dict() for t in pagination.items],
        page, page_size, pagination.total
    ))


@log_bp.route("", methods=["GET"])
def list_logs():
    """分页查询原始日志"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    log_type = request.args.get("log_type")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    username = request.args.get("username")
    keyword = request.args.get("keyword")
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    query = RawLog.query

    if log_type:
        query = query.filter(RawLog.log_type == log_type)
    if src_ip:
        query = query.filter(RawLog.src_ip == src_ip)
    if dst_ip:
        query = query.filter(RawLog.dst_ip == dst_ip)
    if username:
        query = query.filter(RawLog.username == username)
    if start_time:
        query = query.filter(RawLog.event_time >= start_time)
    if end_time:
        query = query.filter(RawLog.event_time <= end_time)
    if keyword:
        query = query.filter(RawLog.raw_content.contains(keyword))

    pagination = query.order_by(RawLog.event_time.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify(paginated_response(
        [r.to_dict() for r in pagination.items],
        page, page_size, pagination.total
    ))


@log_bp.route("/<int:log_id>", methods=["GET"])
def get_log(log_id):
    """查询单条日志详情"""
    log = db.session.get(RawLog, log_id)
    if not log:
        return jsonify(error_response(40401, "日志不存在")), 404
    return jsonify(success_response(log.to_dict()))


@log_bp.route("/deduplicate", methods=["POST"])
def deduplicate_logs():
    """L-10: 日志去重 — 删除重复导入的日志"""
    data = request.get_json() or {}
    log_type = data.get("log_type")
    hours = data.get("hours", 24)

    from app.services.log_parser_service import deduplicate_logs as dedup
    deleted = dedup(log_type=log_type, hours=hours)

    return jsonify(success_response({
        "deleted": deleted,
        "message": f"已删除 {deleted} 条重复日志",
    }))
