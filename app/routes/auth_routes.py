"""认证接口"""
from flask import Blueprint, request, jsonify, redirect, url_for, render_template
from app import db
from app.models.user import User
from app.models.login_log import LoginLog
from app.utils.response import success_response, error_response

auth_bp = Blueprint("auth_routes", __name__)


def _record_login(username, ip, ua, result, reason=None):
    """记录登录尝试"""
    try:
        log = LoginLog(
            username=username,
            ip_address=ip or "unknown",
            user_agent=(ua or "")[:256],
            result=result,
            fail_reason=reason,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """登录：支持表单 POST（页面登录）和 JSON POST（API 登录）"""
    # IP 限流检查 - 防止暴力破解
    from app.utils.security_ext import rate_limiter
    client_ip = request.remote_addr or ""
    if rate_limiter.is_limited(f"login:{client_ip}", max_requests=10, window_seconds=60):
        _record_login("unknown", client_ip, request.headers.get("User-Agent", ""),
                       "fail", "IP 已被限流")
        if not request.is_json:
            return render_template("login.html", error="登录尝试过于频繁，请稍后再试")
        return jsonify(error_response(429, "登录尝试过于频繁，请稍后再试")), 429

    if request.method == "GET":
        # 已登录用户跳转仪表盘
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for("pages.dashboard"))
        return render_template("login.html")

    # POST 处理
    error_msg = None
    username = ""
    password = ""

    # 尝试 JSON
    if request.is_json:
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")
    else:
        # 表单提交
        username = request.form.get("username", "")
        password = request.form.get("password", "")

    if not username or not password:
        error_msg = "用户名和密码不能为空"
    else:
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            error_msg = "用户名或密码错误"
        elif user.status == 0:
            error_msg = "用户已禁用"

    client_ip = request.remote_addr or ""
    ua = request.headers.get("User-Agent", "")

    if error_msg:
        _record_login(username, client_ip, ua, "fail", error_msg)
        # 表单提交 → 渲染登录页带错误
        if not request.is_json:
            return render_template("login.html", error=error_msg)
        return jsonify(error_response(40101, error_msg)), 401

    # 登录成功
    from flask_login import login_user
    login_user(user)
    user.last_login_at = db.func.now()
    db.session.commit()

    _record_login(username, client_ip, ua, "success")

    # 表单提交 → 重定向到首页
    if not request.is_json:
        return redirect(url_for("pages.dashboard"))

    return jsonify(success_response({
        "user": user.to_dict(),
    }))


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    from flask_login import logout_user
    logout_user()
    if request.is_json:
        return jsonify(success_response())
    return redirect(url_for("pages.login_page"))
