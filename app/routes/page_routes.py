"""页面路由：渲染 HTML 模板"""
from flask import Blueprint, render_template, request, redirect, url_for
from flask_login import login_required, current_user, login_user
from app import db
from app.models.user import User

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/login", methods=["GET", "POST"])
def login_page():
    """登录页面：GET 展示表单，POST 处理登录"""
    if current_user.is_authenticated:
        return redirect(url_for("pages.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空")

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return render_template("login.html", error="用户名或密码错误")

        if user.status == 0:
            return render_template("login.html", error="用户已禁用")

        login_user(user)
        user.last_login_at = db.func.now()
        db.session.commit()
        return redirect(url_for("pages.dashboard"))

    return render_template("login.html")


@pages_bp.route("/", methods=["GET"])
@login_required
def dashboard():
    return render_template("dashboard.html")


@pages_bp.route("/alerts", methods=["GET"])
@login_required
def alert_list():
    return render_template("alerts.html")


@pages_bp.route("/alerts/<int:alert_id>", methods=["GET"])
@login_required
def alert_detail(alert_id):
    return render_template("alert_detail.html", alert_id=alert_id)


@pages_bp.route("/logs", methods=["GET"])
@login_required
def log_center():
    return render_template("logs.html")


@pages_bp.route("/chains", methods=["GET"])
@login_required
def chain_list():
    return render_template("chains.html")


@pages_bp.route("/chains/<int:chain_id>", methods=["GET"])
@login_required
def chain_detail(chain_id):
    return render_template("chain_detail.html", chain_id=chain_id)


@pages_bp.route("/reports", methods=["GET"])
@login_required
def report_list():
    return render_template("reports.html")


@pages_bp.route("/reports/<int:report_id>", methods=["GET"])
@login_required
def report_detail(report_id):
    return render_template("report_detail.html", report_id=report_id)


@pages_bp.route("/rules", methods=["GET"])
@login_required
def rule_management():
    return render_template("rules.html")


@pages_bp.route("/configs", methods=["GET"])
@login_required
def system_configs():
    return render_template("configs.html")


@pages_bp.route("/users", methods=["GET"])
@login_required
def user_management():
    return render_template("users.html")


@pages_bp.route("/audit-logs", methods=["GET"])
@login_required
def audit_logs():
    return render_template("audit_logs.html")


@pages_bp.route("/knowledge", methods=["GET"])
@login_required
def knowledge_base():
    return render_template("knowledge.html")


@pages_bp.route("/events", methods=["GET"])
@login_required
def event_list():
    return render_template("events.html")


@pages_bp.route("/alerts/events/<int:event_id>", methods=["GET"])
@login_required
def event_detail(event_id):
    return render_template("event_detail.html", event_id=event_id)


@pages_bp.route("/api-docs", methods=["GET"])
@login_required
def api_docs():
    return render_template("api_docs.html")


@pages_bp.route("/help", methods=["GET"])
@login_required
def help_guide():
    return render_template("help.html")


@pages_bp.route("/login-logs", methods=["GET"])
@login_required
def login_logs_page():
    return render_template("login_logs.html")


@pages_bp.route("/profile", methods=["GET"])
@login_required
def profile_page():
    return render_template("profile.html")


@pages_bp.route("/assets", methods=["GET"])
@login_required
def assets_page():
    return render_template("assets.html")


@pages_bp.route("/assets/<int:asset_id>", methods=["GET"])
@login_required
def asset_detail_page(asset_id: int):
    return render_template("asset_detail.html", asset_id=asset_id)
