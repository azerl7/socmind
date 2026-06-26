"""数据导出 API"""
from flask import Blueprint, request, jsonify, Response
from flask_login import login_required

from app.services.export_service import (
    export_alerts_csv, export_alerts_json,
    export_logs_csv, export_chains_csv, export_chain_detail_json,
)

export_bp = Blueprint("export", __name__)


@export_bp.route("/alerts/csv", methods=["GET"])
@login_required
def export_alerts_csv_api():
    """导出告警 CSV"""
    severity = request.args.get("severity")
    status = request.args.get("status")
    attack_type = request.args.get("attack_type")
    src_ip = request.args.get("src_ip")

    content = export_alerts_csv(
        severity=severity, status=status,
        attack_type=attack_type, src_ip=src_ip,
    )
    return Response(
        "\ufeff" + content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=alerts_{request.args.get('_t', 'export')}.csv"},
    )


@export_bp.route("/alerts/json", methods=["GET"])
@login_required
def export_alerts_json_api():
    """导出告警 JSON"""
    severity = request.args.get("severity")
    status = request.args.get("status")
    attack_type = request.args.get("attack_type")
    src_ip = request.args.get("src_ip")

    content = export_alerts_json(
        severity=severity, status=status,
        attack_type=attack_type, src_ip=src_ip,
    )
    return Response(
        content,
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=alerts_{request.args.get('_t', 'export')}.json"},
    )


@export_bp.route("/logs/csv", methods=["GET"])
@login_required
def export_logs_csv_api():
    """导出日志 CSV"""
    log_type = request.args.get("log_type")
    src_ip = request.args.get("src_ip")
    keyword = request.args.get("keyword")

    content = export_logs_csv(log_type=log_type, src_ip=src_ip, keyword=keyword)
    return Response(
        content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=logs_export.csv"},
    )


@export_bp.route("/chains/csv", methods=["GET"])
@login_required
def export_chains_csv_api():
    """导出攻击链 CSV"""
    content = export_chains_csv()
    return Response(
        content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=chains_export.csv"},
    )


@export_bp.route("/chains/<int:chain_id>/json", methods=["GET"])
@login_required
def export_chain_detail_json_api(chain_id: int):
    """导出攻击链详情 JSON"""
    content = export_chain_detail_json(chain_id)
    if content is None:
        return jsonify({"code": 404, "message": "攻击链不存在"}), 404
    return Response(
        content,
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=chain_{chain_id}.json"},
    )
