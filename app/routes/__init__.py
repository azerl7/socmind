"""注册所有路由蓝图"""
from flask import Flask


def register_routes(app: Flask):
    from app.routes.auth_routes import auth_bp
    from app.routes.log_routes import log_bp
    from app.routes.rule_routes import rule_bp
    from app.routes.alert_routes import alert_bp
    from app.routes.ai_routes import ai_bp
    from app.routes.chain_routes import chain_bp
    from app.routes.report_routes import report_bp
    from app.routes.config_routes import config_bp
    from app.routes.page_routes import pages_bp
    from app.routes.dashboard_routes import dashboard_bp
    from app.routes.user_routes import user_bp
    from app.routes.system_routes import system_bp
    from app.routes.knowledge_routes import knowledge_bp
    from app.routes.notification_routes import notification_bp
    from app.routes.asset_routes import asset_bp
    from app.routes.scheduler_routes import scheduler_bp
    from app.routes.export_routes import export_bp
    from app.routes.search_routes import search_bp
    from app.routes.comment_routes import comment_bp
    from app.routes.suppression_routes import suppression_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(log_bp, url_prefix="/api/v1/logs")
    app.register_blueprint(rule_bp, url_prefix="/api/v1/rules")
    app.register_blueprint(alert_bp, url_prefix="/api/v1/alerts")
    app.register_blueprint(ai_bp, url_prefix="/api/v1/ai")
    app.register_blueprint(chain_bp, url_prefix="/api/v1/attack-chains")
    app.register_blueprint(report_bp, url_prefix="/api/v1/reports")
    app.register_blueprint(config_bp, url_prefix="/api/v1/configs")
    app.register_blueprint(pages_bp)
    app.register_blueprint(dashboard_bp, url_prefix="/api/v1/dashboard")
    app.register_blueprint(user_bp, url_prefix="/api/v1/users")
    app.register_blueprint(system_bp, url_prefix="/api/v1/system")
    app.register_blueprint(knowledge_bp, url_prefix="/api/v1/knowledge")
    app.register_blueprint(notification_bp, url_prefix="/api/v1/notifications")
    app.register_blueprint(asset_bp, url_prefix="/api/v1/assets")
    app.register_blueprint(scheduler_bp, url_prefix="/api/v1/scheduler")
    app.register_blueprint(export_bp, url_prefix="/api/v1/export")
    app.register_blueprint(search_bp, url_prefix="/api/v1/search")
    app.register_blueprint(comment_bp, url_prefix="/api/v1/comments")
    app.register_blueprint(suppression_bp, url_prefix="/api/v1/suppressions")
