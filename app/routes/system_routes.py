"""系统管理接口：演示数据导入、健康检查、审计日志"""
import os
import json
import subprocess
import sys
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app

from app import db
from app.models.config import AuditLog
from app.utils.response import success_response, error_response

system_bp = Blueprint("system_routes", __name__)


@system_bp.route("/health", methods=["GET"])
def health_check():
    """系统健康检查"""
    results = {}

    # 数据库检查
    try:
        db.session.execute(db.text("SELECT 1"))
        results["database"] = "ok"
    except Exception as e:
        results["database"] = f"error: {e}"

    # 规则检查
    from app.models.rule import DetectionRule
    try:
        rule_count = DetectionRule.query.count()
        results["rules"] = f"ok ({rule_count} rules)"
    except Exception as e:
        results["rules"] = f"error: {e}"

    # 配置检查
    from app.models.config import SystemConfig
    try:
        cfg_count = SystemConfig.query.count()
        openai_key = SystemConfig.query.filter_by(config_key="openai_api_key").first()
        results["openai"] = "configured" if (openai_key and openai_key.config_value) else "not configured"
    except Exception as e:
        results["openai"] = f"error: {e}"

    # 目录检查
    upload_dir = current_app.config.get("UPLOAD_FOLDER", "")
    results["uploads"] = "ok" if os.path.isdir(upload_dir) else "missing"

    all_ok = all(v == "ok" or v.startswith("ok") for v in results.values())
    return jsonify(success_response({
        "status": "healthy" if all_ok else "degraded",
        "checks": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))


@system_bp.route("/demo/import", methods=["POST"])
def import_demo_data():
    """一键导入演示数据

    1. 检查 demo_data 目录是否存在演示日志文件
    2. 调用日志解析服务导入
    3. 执行规则检测
    """
    from app.services.log_parser_service import process_import_task, parse_log_content
    from app.services.rule_engine_service import run_detection
    from app.models.log import RawLog, LogImportTask

    demo_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "demo_data")
    if not os.path.isdir(demo_dir):
        return jsonify(error_response(40001, "演示数据目录不存在，请先运行 generate_demo_logs.py")), 400

    # 查找演示日志文件
    log_files = {
        "web": os.path.join(demo_dir, "web_access.log"),
        "login": os.path.join(demo_dir, "login_logs.csv"),
        "waf": os.path.join(demo_dir, "waf_alerts.json"),
        "host": os.path.join(demo_dir, "host_auth.log"),
        "network": os.path.join(demo_dir, "suricata_eve.json"),
    }

    results = []
    total_alerts = 0

    for log_type, fpath in log_files.items():
        if not os.path.isfile(fpath):
            results.append({"type": log_type, "status": "skipped", "message": "文件不存在"})
            continue

        # 读取文件内容
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # 直接解析入库
        success_count = 0
        batch = []
        for parsed in parse_log_content(content, log_type, f"demo_{log_type}"):
            log = RawLog(
                log_type=parsed.get("log_type", log_type),
                source=parsed.get("source", f"demo_{log_type}"),
                event_time=parsed.get("event_time"),
                src_ip=parsed.get("src_ip"),
                dst_ip=parsed.get("dst_ip"),
                username=parsed.get("username"),
                http_method=parsed.get("http_method"),
                url=parsed.get("url"),
                status_code=parsed.get("status_code"),
                user_agent=parsed.get("user_agent"),
                action=parsed.get("action"),
                result=parsed.get("result"),
                raw_content=parsed.get("raw_content", ""),
                parsed_json=parsed.get("parsed_json"),
            )
            batch.append(log)
            success_count += 1

            if len(batch) >= 200:
                db.session.bulk_save_objects(batch)
                batch.clear()

        if batch:
            db.session.bulk_save_objects(batch)
        db.session.commit()

        results.append({"type": log_type, "status": "imported", "count": success_count})

        # 对该类型执行规则检测
        det_result = run_detection(log_type=log_type)
        total_alerts += det_result["alert_count"]

    # 如果有告警，自动聚合和生成攻击链
    if total_alerts > 0:
        from app.services.attack_chain_service import generate_attack_chain
        chain = generate_attack_chain()
        results.append({"type": "attack_chain", "status": "generated", "chain_id": chain.get("chain_id")})

    # 自动发现资产
    try:
        from app.services.asset_service import discover_assets
        discover_assets()
    except Exception:
        pass

    return jsonify(success_response({
        "imports": results,
        "total_alerts": total_alerts,
        "message": f"演示数据导入完成，共生成 {total_alerts} 条告警",
    }))


@system_bp.route("/audit-logs", methods=["GET"])
def list_audit_logs():
    """查询审计日志"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    action = request.args.get("action")

    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action == action)

    pagination = query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify(success_response({
        "items": [a.to_dict() for a in pagination.items],
        "page": page,
        "page_size": page_size,
        "total": pagination.total,
    }))


@system_bp.route("/login-logs", methods=["GET"])
def list_login_logs():
    """查询登录日志"""
    from app.models.login_log import LoginLog
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    username = request.args.get("username")
    result = request.args.get("result")

    query = LoginLog.query
    if username:
        query = query.filter(LoginLog.username == username)
    if result:
        query = query.filter(LoginLog.result == result)

    pagination = query.order_by(LoginLog.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify(success_response({
        "items": [l.to_dict() for l in pagination.items],
        "page": page,
        "page_size": page_size,
        "total": pagination.total,
    }))


@system_bp.route("/audit-logs", methods=["POST"])
def add_audit_log():
    data = request.get_json() or {}
    log = AuditLog(
        user_id=data.get("user_id"), username=data.get("username"),
        action=data.get("action", ""), target_type=data.get("target_type"),
        target_id=data.get("target_id"), detail=data.get("detail", ""),
    )
    db.session.add(log)
    db.session.commit()
    return jsonify(success_response({"id": log.id}))
