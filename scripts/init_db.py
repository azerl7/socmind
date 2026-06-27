#!/usr/bin/env python3
"""数据库初始化脚本：建库、建表、种子数据

用法:
    python scripts/init_db.py              # 初始化（保留已有表）
    python scripts/init_db.py --force      # 强制重建（删除所有表后重建）
"""
import sys
import os

# 将项目根目录加入 sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models import *  # noqa: F401, F403 — 确保所有模型被加载


def init_database(force=False):
    """创建所有表并写入种子数据"""
    app = create_app("development")

    with app.app_context():
        if force:
            print("[INFO] 强制重建模式：删除所有表...")
            db.drop_all()
            print("[OK] 所有表已删除")

        print("[INFO] 正在创建数据库表...")
        db.create_all()
        print("[OK] 数据库表创建完成")

        # ── 迁移：检查并添加缺失列 ──
        print("[INFO] 检查数据库表结构兼容性...")
        try:
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)

            # 检查 alerts 表缺失列
            if "alerts" in inspector.get_table_names():
                alert_columns = [c["name"] for c in inspector.get_columns("alerts")]
                missing_alert_cols = []
                if "assigned_to" not in alert_columns:
                    missing_alert_cols.append("ADD COLUMN assigned_to INT DEFAULT NULL")
                if "assigned_username" not in alert_columns:
                    missing_alert_cols.append("ADD COLUMN assigned_username VARCHAR(64) DEFAULT NULL")
                if missing_alert_cols:
                    for col_def in missing_alert_cols:
                        db.session.execute(text(f"ALTER TABLE alerts {col_def}"))
                    db.session.commit()
                    print(f"[OK] alerts 表补充了 {len(missing_alert_cols)} 个缺失列")

            # 检查 ai_analyses 表缺失列
            if "ai_analyses" in inspector.get_table_names():
                ai_columns = [c["name"] for c in inspector.get_columns("ai_analyses")]
                missing_ai_cols = []
                if "is_revised" not in ai_columns:
                    missing_ai_cols.append("ADD COLUMN is_revised TINYINT DEFAULT 0")
                if "revised_by" not in ai_columns:
                    missing_ai_cols.append("ADD COLUMN revised_by INT DEFAULT NULL")
                if "revised_by_name" not in ai_columns:
                    missing_ai_cols.append("ADD COLUMN revised_by_name VARCHAR(64) DEFAULT NULL")
                if "revised_at" not in ai_columns:
                    missing_ai_cols.append("ADD COLUMN revised_at DATETIME DEFAULT NULL")
                if "revision_comment" not in ai_columns:
                    missing_ai_cols.append("ADD COLUMN revision_comment TEXT DEFAULT NULL")
                if missing_ai_cols:
                    for col_def in missing_ai_cols:
                        db.session.execute(text(f"ALTER TABLE ai_analyses {col_def}"))
                    db.session.commit()
                    print(f"[OK] ai_analyses 表补充了 {len(missing_ai_cols)} 个缺失列")

            # 检查 assets 表
            if "assets" not in inspector.get_table_names():
                print("[INFO] assets 表将在下次启动时由 SQLAlchemy 自动创建")

        except Exception as e:
            print(f"[WARN] 表结构兼容性检查跳过: {e}")

        # ———— 种子数据 ————

        # 1. 角色
        from app.models.user import Role
        roles_data = [
            {"role_code": "admin", "role_name": "系统管理员", "description": "系统管理员，拥有所有权限"},
            {"role_code": "analyst", "role_name": "安全分析员", "description": "安全分析员，可进行研判和操作"},
            {"role_code": "viewer", "role_name": "只读用户", "description": "只读用户，仅可查看数据"},
        ]
        for r in roles_data:
            if not Role.query.filter_by(role_code=r["role_code"]).first():
                db.session.add(Role(**r))
        db.session.commit()
        print("[OK] 角色数据初始化完成")

        # 2. 管理员用户
        from app.models.user import User, UserRole
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                nickname="管理员",
                email="admin@socmind.local",
                status=1,
            )
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()

            # 关联 admin 角色
            admin_role = Role.query.filter_by(role_code="admin").first()
            if admin_role:
                db.session.add(UserRole(user_id=admin.id, role_id=admin_role.id))
                db.session.commit()
            print("[OK] 管理员用户初始化完成 (admin / admin123)")
        else:
            print("[INFO] 管理员用户已存在")

        # 3. 攻击阶段字典
        from app.models.attack_chain import AttackStage
        stages_data = [
            {"stage_code": "recon", "stage_name": "扫描探测", "stage_order": 1, "framework": "web_chain",
             "description": "攻击者收集目标信息，包括高频访问、目录扫描"},
            {"stage_code": "sensitive_path", "stage_name": "敏感路径访问", "stage_order": 2, "framework": "web_chain",
             "description": "攻击者访问敏感路径，如 /admin、/.git、/backup"},
            {"stage_code": "exploit_attempt", "stage_name": "漏洞尝试", "stage_order": 3, "framework": "web_chain",
             "description": "攻击者尝试利用漏洞，如 SQL 注入、XSS、命令执行"},
            {"stage_code": "abnormal_login", "stage_name": "异常登录", "stage_order": 4, "framework": "web_chain",
             "description": "异常登录行为，如暴力破解、异常时间段登录"},
            {"stage_code": "suspicious_action", "stage_name": "可疑行为", "stage_order": 5, "framework": "web_chain",
             "description": "可疑操作，如 Webshell 访问、异常命令执行"},
            {"stage_code": "data_access", "stage_name": "敏感数据访问", "stage_order": 6, "framework": "web_chain",
             "description": "攻击者访问或试图导出敏感数据"},
        ]
        for s in stages_data:
            if not AttackStage.query.filter_by(stage_code=s["stage_code"]).first():
                db.session.add(AttackStage(**s))
        db.session.commit()
        print("[OK] 攻击阶段字典初始化完成")

        # 4. MITRE ATT&CK 阶段
        mitre_stages = [
            {"stage_code": "reconnaissance", "stage_name": "Reconnaissance 侦察", "stage_order": 1,
             "framework": "mitre_attack", "description": "攻击者收集目标信息"},
            {"stage_code": "initial_access", "stage_name": "Initial Access 初始访问", "stage_order": 2,
             "framework": "mitre_attack", "description": "攻击者尝试进入系统"},
            {"stage_code": "execution", "stage_name": "Execution 执行", "stage_order": 3, "framework": "mitre_attack",
             "description": "执行恶意动作"},
            {"stage_code": "persistence", "stage_name": "Persistence 持久化", "stage_order": 4,
             "framework": "mitre_attack", "description": "维持访问"},
            {"stage_code": "privilege_escalation", "stage_name": "Privilege Escalation 权限提升", "stage_order": 5,
             "framework": "mitre_attack", "description": "尝试提高权限"},
            {"stage_code": "defense_evasion", "stage_name": "Defense Evasion 防御规避", "stage_order": 6,
             "framework": "mitre_attack", "description": "规避检测"},
            {"stage_code": "credential_access", "stage_name": "Credential Access 凭据访问", "stage_order": 7,
             "framework": "mitre_attack", "description": "获取账号凭据"},
            {"stage_code": "lateral_movement", "stage_name": "Lateral Movement 横向移动", "stage_order": 8,
             "framework": "mitre_attack", "description": "扩展到其他主机"},
            {"stage_code": "collection", "stage_name": "Collection 收集", "stage_order": 9,
             "framework": "mitre_attack", "description": "访问敏感数据"},
            {"stage_code": "exfiltration", "stage_name": "Exfiltration 数据外传", "stage_order": 10,
             "framework": "mitre_attack", "description": "数据传出"},
        ]
        for s in mitre_stages:
            if not AttackStage.query.filter_by(stage_code=s["stage_code"]).first():
                db.session.add(AttackStage(**s))
        db.session.commit()
        print("[OK] MITRE ATT&CK 阶段初始化完成")

        # 5. 检测规则
        from scripts.seed_rules import seed_rules
        seed_rules()
        print("[OK] 检测规则初始化完成")

        # 6. 系统默认配置
        from app.models.config import SystemConfig
        default_configs = [
            # ── 旧版兼容(将被 ai_provider_* 替代) ──
            {"config_key": "openai_api_key", "config_value": "", "config_type": "secret",
             "description": "OpenAI API Key (旧版兼容)"},
            {"config_key": "openai_model", "config_value": "gpt-4o-mini", "config_type": "string",
             "description": "模型名称 (旧版兼容)"},
            {"config_key": "openai_base_url", "config_value": "", "config_type": "string", "description": "API Base URL (旧版兼容)"},

            # ── 多 Provider 配置 ──
            {"config_key": "ai_provider", "config_value": "openai", "config_type": "string",
             "description": "当前 AI Provider: openai / deepseek / qwen / minimax"},

            # OpenAI
            {"config_key": "ai_provider_openai_api_key", "config_value": "", "config_type": "secret",
             "description": "OpenAI API Key"},
            {"config_key": "ai_provider_openai_model", "config_value": "gpt-4o-mini", "config_type": "string",
             "description": "OpenAI 模型名称"},
            {"config_key": "ai_provider_openai_base_url", "config_value": "https://api.openai.com/v1", "config_type": "string",
             "description": "OpenAI API Base URL"},

            # DeepSeek
            {"config_key": "ai_provider_deepseek_api_key", "config_value": "", "config_type": "secret",
             "description": "DeepSeek API Key"},
            {"config_key": "ai_provider_deepseek_model", "config_value": "deepseek-chat", "config_type": "string",
             "description": "DeepSeek 模型名称"},
            {"config_key": "ai_provider_deepseek_base_url", "config_value": "https://api.deepseek.com/v1", "config_type": "string",
             "description": "DeepSeek API Base URL"},

            # Qwen (通义千问)
            {"config_key": "ai_provider_qwen_api_key", "config_value": "", "config_type": "secret",
             "description": "通义千问 API Key (DashScope)"},
            {"config_key": "ai_provider_qwen_model", "config_value": "qwen-turbo", "config_type": "string",
             "description": "通义千问模型名称"},
            {"config_key": "ai_provider_qwen_base_url", "config_value": "https://dashscope.aliyuncs.com/compatible-mode/v1", "config_type": "string",
             "description": "通义千问 API Base URL (OpenAI 兼容)"},

            # MiniMax
            {"config_key": "ai_provider_minimax_api_key", "config_value": "", "config_type": "secret",
             "description": "MiniMax API Key"},
            {"config_key": "ai_provider_minimax_model", "config_value": "abab6.5s-chat", "config_type": "string",
             "description": "MiniMax 模型名称"},
            {"config_key": "ai_provider_minimax_base_url", "config_value": "https://api.minimax.chat/v1", "config_type": "string",
             "description": "MiniMax API Base URL"},
            {"config_key": "brute_force_threshold", "config_value": "5", "config_type": "number",
             "description": "暴力破解阈值(同IP失败次数)"},
            {"config_key": "alert_time_window_minutes", "config_value": "10", "config_type": "number",
             "description": "告警聚合时间窗口(分钟)"},
            {"config_key": "high_freq_threshold", "config_value": "100", "config_type": "number",
             "description": "高频访问阈值(次/分钟)"},
            {"config_key": "port_scan_threshold", "config_value": "20", "config_type": "number",
             "description": "端口扫描阈值(不同端口数)"},
            # 通知配置
            {"config_key": "notification_enabled", "config_value": "false", "config_type": "string",
             "description": "启用通知(true/false)"},
            {"config_key": "notification_min_severity", "config_value": "high", "config_type": "string",
             "description": "通知最低告警等级(low/medium/high/critical)"},
            {"config_key": "webhook_url", "config_value": "", "config_type": "secret",
             "description": "Webhook URL(企业微信/钉钉/飞书/通用)"},
            {"config_key": "webhook_type", "config_value": "generic", "config_type": "string",
             "description": "Webhook类型(generic/wechat/dingtalk/feishu)"},
            {"config_key": "smtp_host", "config_value": "", "config_type": "string",
             "description": "SMTP 服务器地址"},
            {"config_key": "smtp_port", "config_value": "587", "config_type": "number",
             "description": "SMTP 端口"},
            {"config_key": "smtp_username", "config_value": "", "config_type": "string",
             "description": "SMTP 用户名"},
            {"config_key": "smtp_password", "config_value": "", "config_type": "secret",
             "description": "SMTP 密码"},
            {"config_key": "notification_email_to", "config_value": "", "config_type": "string",
             "description": "告警通知接收邮箱"},
            # 定时任务配置
            {"config_key": "scheduler_daily_report", "config_value": "false", "config_type": "string",
             "description": "启用每日报告生成(true/false)"},
            {"config_key": "scheduler_weekly_report", "config_value": "false", "config_type": "string",
             "description": "启用每周报告生成(true/false)"},
            {"config_key": "scheduler_monthly_report", "config_value": "false", "config_type": "string",
             "description": "启用每月报告生成(true/false)"},
            {"config_key": "scheduler_daily_cron", "config_value": "0 9 * * *", "config_type": "string",
             "description": "每日报告 cron 表达式"},
            {"config_key": "scheduler_weekly_cron", "config_value": "0 9 * * 1", "config_type": "string",
             "description": "每周报告 cron 表达式"},
            {"config_key": "scheduler_monthly_cron", "config_value": "0 9 1 * *", "config_type": "string",
             "description": "每月报告 cron 表达式"},
            # 告警升级配置
            {"config_key": "escalation_enabled", "config_value": "false", "config_type": "string",
             "description": "启用告警自动升级(true/false)"},
            {"config_key": "escalation_critical_hours", "config_value": "1", "config_type": "number",
             "description": "严重告警升级阈值(小时)"},
            {"config_key": "escalation_high_hours", "config_value": "4", "config_type": "number",
             "description": "高危告警升级阈值(小时)"},
            {"config_key": "escalation_medium_hours", "config_value": "12", "config_type": "number",
             "description": "中危告警升级阈值(小时)"},
            {"config_key": "escalation_max_count", "config_value": "3", "config_type": "number",
             "description": "最大升级次数"},
            {"config_key": "blocked_ips", "config_value": "", "config_type": "string",
             "description": "被封禁 IP 列表(逗号分隔)"},
            # 数据保留配置
            {"config_key": "retention_raw_logs", "config_value": "90", "config_type": "number",
             "description": "原始日志保留天数"},
            {"config_key": "retention_alerts", "config_value": "365", "config_type": "number",
             "description": "已关闭告警保留天数"},
            {"config_key": "retention_login_logs", "config_value": "180", "config_type": "number",
             "description": "登录日志保留天数"},
            {"config_key": "retention_audit_logs", "config_value": "365", "config_type": "number",
             "description": "审计日志保留天数"},
        ]
        for c in default_configs:
            if not SystemConfig.query.filter_by(config_key=c["config_key"]).first():
                db.session.add(SystemConfig(**c))
        db.session.commit()
        print("[OK] 系统默认配置初始化完成")

        # 7. 加载知识库文件
        from app.services.rag_service import _load_knowledge_base_files
        _load_knowledge_base_files()
        print("[OK] 安全知识库加载完成")

    print("\n[SUCCESS] 数据库初始化全部完成！")
    print("  管理员账号: admin / admin123")


if __name__ == "__main__":
    force = "--force" in sys.argv
    init_database(force=force)
