"""报告接口 — 接入 report_service"""
from flask import Blueprint, request, jsonify, render_template
from app.services.report_service import (
    generate_alert_report,
    generate_chain_report,
    get_report,
    list_reports,
)
from app.utils.response import success_response, error_response, paginated_response
from flask_login import login_required, current_user

report_bp = Blueprint("report_routes", __name__)


@report_bp.route("/generate", methods=["POST"])
def generate():
    """生成报告"""
    data = request.get_json() or {}
    report_type = data.get("report_type", "alert")
    target_id = data.get("target_id")
    use_ai_polish = data.get("use_ai_polish", False)

    if not target_id:
        return jsonify(error_response(40001, "缺少 target_id")), 400

    if report_type == "alert":
        result = generate_alert_report(target_id, use_ai=use_ai_polish)
    elif report_type == "chain":
        result = generate_chain_report(target_id, use_ai_polish=use_ai_polish)
    else:
        return jsonify(error_response(40001, f"不支持的报告类型: {report_type}")), 400

    if "error" in result:
        code = result.get("code", 40401)
        return jsonify(error_response(code, result["error"])), (404 if code == 40401 else 500)

    return jsonify(success_response({
        "report_id": result["report_id"],
        "report_no": result["report_no"],
        "title": result["title"],
    }))


@report_bp.route("", methods=["GET"])
def list_reports_endpoint():
    """查询报告列表"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    result = list_reports(page=page, page_size=page_size)
    return jsonify(paginated_response(
        result["items"], result["page"], result["page_size"], result["total"]
    ))


@report_bp.route("/<int:report_id>", methods=["GET"])
def get_report_endpoint(report_id):
    """查询报告详情"""
    report = get_report(report_id)
    if not report:
        return jsonify(error_response(40401, "报告不存在")), 404
    return jsonify(success_response(report))


@report_bp.route("/<int:report_id>/print", methods=["GET"])
def print_report(report_id):
    """打印优化版报告页面（适合浏览器另存为 PDF）"""
    report = get_report(report_id)
    if not report:
        return jsonify(error_response(40401, "报告不存在")), 404
    return render_template("report_print.html", report=report)


@report_bp.route("/<int:report_id>/pdf", methods=["GET"])
def download_pdf(report_id):
    """服务端 PDF 生成（尝试 weasyprint，失败则引导使用打印功能）"""
    report = get_report(report_id)
    if not report:
        return jsonify(error_response(40401, "报告不存在")), 404

    html = render_template("report_print.html", report=report)

    try:
        import weasyprint
        pdf = weasyprint.HTML(string=html).write_pdf()
        from flask import make_response
        response = make_response(pdf)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="report-{report_id}.pdf"'
        return response
    except ImportError:
        # weasyprint 未安装，引导用户使用浏览器打印功能
        return jsonify(success_response({
            "message": "服务端 PDF 生成需要安装 weasyprint (pip install weasyprint)，当前请使用浏览器打印功能",
            "print_url": f"/api/v1/reports/{report_id}/print",
        }))


@report_bp.route("/templates", methods=["GET"])
def list_templates():
    from app.models.report import ReportTemplate
    templates = ReportTemplate.query.order_by(ReportTemplate.id).all()
    return jsonify(success_response([t.to_dict() for t in templates]))


@report_bp.route("/templates", methods=["POST"])
@login_required
def create_template():
    from app.models.report import ReportTemplate
    data = request.get_json() or {}
    if not data.get("name"):
        return jsonify(error_response(40001, "模板名称不能为空")), 400
    template = ReportTemplate(
        name=data["name"], description=data.get("description", ""),
        template_type=data.get("template_type", "chain"),
        content_template=data.get("content_template", ""),
        created_by=current_user.username,
    )
    db.session.add(template)
    db.session.commit()
    return jsonify(success_response(template.to_dict())), 201


@report_bp.route("/templates/<int:template_id>", methods=["PUT"])
@login_required
def update_template(template_id):
    from app.models.report import ReportTemplate
    template = db.session.get(ReportTemplate, template_id)
    if not template:
        return jsonify(error_response(40401, "模板不存在")), 404
    for field in ["name", "description", "template_type", "content_template"]:
        if field in request.get_json():
            setattr(template, field, request.get_json()[field])
    db.session.commit()
    return jsonify(success_response(template.to_dict()))


@report_bp.route("/templates/<int:template_id>", methods=["DELETE"])
@login_required
def delete_template(template_id):
    from app.models.report import ReportTemplate
    template = db.session.get(ReportTemplate, template_id)
    if not template:
        return jsonify(error_response(40401, "模板不存在")), 404
    db.session.delete(template)
    db.session.commit()
    return jsonify(success_response({"deleted": True}))
