#!/usr/bin/env python3
"""SOCMind 管理 CLI

用法:
    python manage.py init_db          初始化数据库
    python manage.py create_admin     创建管理员用户
    python manage.py reset_password <username> <password>
    python manage.py stats            显示平台统计
    python manage.py purge            手动清理过期数据
    python manage.py export_rules     导出所有检测规则
    python manage.py backup_db        备份数据库
    python manage.py health           健康检查
"""
import sys
import os
import json
import shutil
from datetime import datetime

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def get_app():
    from app import create_app, db
    app = create_app("development")
    return app, db


def cmd_init_db():
    """初始化数据库"""
    from scripts.init_db import init_database
    init_database()
    print("[OK] 数据库初始化完成")


def cmd_create_admin():
    """创建管理员用户"""
    from app.models.user import User, Role, UserRole
    from getpass import getpass

    app, db = get_app()
    with app.app_context():
        username = input("用户名 (默认: admin): ").strip() or "admin"
        password = getpass("密码 (默认: admin123): ").strip() or "admin123"
        email = input("邮箱: ").strip() or f"{username}@socmind.local"

        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"[!] 用户 {username} 已存在")
            return

        user = User(username=username, nickname="管理员", email=email, status=1)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        admin_role = Role.query.filter_by(role_code="admin").first()
        if admin_role:
            db.session.add(UserRole(user_id=user.id, role_id=admin_role.id))

        db.session.commit()
        print(f"[OK] 管理员用户已创建: {username}")


def cmd_reset_password():
    """重置用户密码"""
    if len(sys.argv) < 4:
        print("用法: python manage.py reset_password <username> <password>")
        return

    username = sys.argv[2]
    password = sys.argv[3]

    from app.models.user import User
    app, db = get_app()
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"[!] 用户不存在: {username}")
            return
        user.set_password(password)
        db.session.commit()
        print(f"[OK] 密码已重置: {username}")


def cmd_stats():
    """显示平台统计"""
    app, db = get_app()
    with app.app_context():
        from app.models.alert import Alert
        from app.models.log import RawLog
        from app.models.attack_chain import AttackChain
        from app.models.report import Report
        from app.models.user import User
        from app.models.asset import Asset
        from app.models.rule import DetectionRule

        print("=" * 50)
        print("  SOCMind 平台统计")
        print("=" * 50)
        print(f"  用户:     {User.query.count()}")
        print(f"  资产:     {Asset.query.count()}")
        print(f"  规则:     {DetectionRule.query.count()}")
        print(f"  日志:     {RawLog.query.count()}")
        print(f"  告警:     {Alert.query.count()}")
        print(f"  攻击链:   {AttackChain.query.count()}")
        print(f"  报告:     {Report.query.count()}")
        print(f"  时间:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)


def cmd_purge():
    """手动清理过期数据"""
    app, db = get_app()
    with app.app_context():
        from app.services.retention_service import purge_old_data
        result = purge_old_data()
        print(f"[OK] 清理完成: {json.dumps(result, ensure_ascii=False)}")


def cmd_export_rules():
    """导出检测规则"""
    app, db = get_app()
    with app.app_context():
        from app.models.rule import DetectionRule
        rules = DetectionRule.query.all()
        data = [r.to_dict() for r in rules]
        filename = f"socmind_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[OK] 规则已导出: {filename} ({len(data)} 条)")


def cmd_backup_db():
    """备份数据库"""
    from config import config_map

    app, db = get_app()
    db_url = app.config.get("SQLALCHEMY_DATABASE_URI", "")

    backup_dir = "backups"
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if "sqlite" in db_url:
        # SQLite 备份 - 直接拷贝文件
        db_path = db_url.replace("sqlite:///", "")
        if db_path.startswith("/"):
            backup_path = os.path.join(backup_dir, f"socmind_db_{timestamp}.sqlite")
        else:
            backup_path = os.path.join(backup_dir, f"socmind_db_{timestamp}.sqlite")
            db_path = os.path.join(os.path.dirname(__file__), "instance", db_path)

        if os.path.exists(db_path):
            shutil.copy2(db_path, backup_path)
            print(f"[OK] SQLite 数据库已备份: {backup_path}")
        else:
            print(f"[!] 数据库文件不存在: {db_path}")
    elif "mysql" in db_url:
        # MySQL 备份 - 使用 mysqldump
        import re
        m = re.match(r"mysql\+pymysql://([^:]+):([^@]+)@([^:]+):(\d+)/([^?]+)", db_url)
        if m:
            user, pwd, host, port, dbname = m.groups()
            backup_path = os.path.join(backup_dir, f"socmind_mysql_{timestamp}.sql")
            cmd = f"mysqldump -h {host} -P {port} -u {user} -p{pwd} {dbname} > {backup_path}"
            ret = os.system(cmd)
            if ret == 0:
                print(f"[OK] MySQL 数据库已备份: {backup_path}")
            else:
                print("[!] MySQL 备份失败，请确保 mysqldump 已安装")
        else:
            print("[!] 无法解析数据库连接字符串")
    else:
        print(f"[!] 不支持的数据库类型: {db_url}")

    print(f"[OK] 备份目录: {os.path.abspath(backup_dir)}")


def cmd_health():
    """健康检查"""
    app, db = get_app()
    with app.app_context():
        try:
            db.session.execute(db.text("SELECT 1"))
            print("[OK] 数据库连接正常")
        except Exception as e:
            print(f"[!] 数据库异常: {e}")

        from app.models.rule import DetectionRule
        from app.models.alert import Alert
        try:
            rule_count = DetectionRule.query.count()
            print(f"[OK] 规则引擎: {rule_count} 条规则")
            alert_new = Alert.query.filter_by(status="new").count()
            print(f"[OK] 待处理告警: {alert_new}")
        except Exception as e:
            print(f"[!] 查询异常: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    commands = {
        "init_db": cmd_init_db,
        "create_admin": cmd_create_admin,
        "reset_password": cmd_reset_password,
        "stats": cmd_stats,
        "purge": cmd_purge,
        "export_rules": cmd_export_rules,
        "backup_db": cmd_backup_db,
        "health": cmd_health,
    }

    cmd = commands.get(command)
    if cmd:
        cmd()
    else:
        print(f"[!] 未知命令: {command}")
        print(f"    可用命令: {', '.join(commands.keys())}")
