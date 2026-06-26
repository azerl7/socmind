"""SOCMind Flask 应用工厂"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import config_map

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "pages.login_page"


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_map.get(config_name, config_map["development"]))

    # 确保上传目录存在
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    # 注册蓝图
    from app.routes import register_routes
    register_routes(app)

    # 安全初始化
    if config_name != "testing":
        try:
            from app.utils.security_ext import init_csrf, add_security_headers
            init_csrf(app)
            app.after_request(add_security_headers)
        except Exception:
            pass

    # 注册错误页面处理器
    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template, redirect, url_for
        from flask_login import current_user
        if not current_user.is_authenticated:
            return redirect(url_for("pages.login_page"))
        return render_template("404.html"), 404

    # 初始化后台调度器（生产环境才启动）
    if config_name != "testing":
        try:
            from app.services.scheduler_service import init_scheduler
            init_scheduler(app)
        except Exception:
            pass

    return app
