#!/usr/bin/env python3
"""一键导入演示数据到系统（CLI 版本）

使用方法:
    python scripts/import_demo_data.py

自动执行:
    1. 生成演示日志文件
    2. 解析并导入所有日志到数据库
    3. 执行规则检测生成告警
    4. 聚合告警并生成攻击链
    5. 自动发现资产
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.log import RawLog
from app.models.alert import Alert
from app.models.attack_chain import AttackChain


def main():
    print("=" * 60)
    print("SOCMind 演示数据一键导入工具")
    print("=" * 60)

    # Step 1: 生成演示日志文件
    print("\n[1/5] 生成演示日志文件...")
    from scripts.generate_demo_logs import main as gen_logs
    gen_logs()

    # Step 2: 导入日志到数据库
    print("\n[2/5] 导入日志到数据库...")
    app = create_app("development")

    with app.app_context():
        from app.services.log_parser_service import parse_log_content

        demo_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demo_data")
        log_files = {
            "web": os.path.join(demo_dir, "web_access.log"),
            "login": os.path.join(demo_dir, "login_logs.csv"),
            "waf": os.path.join(demo_dir, "waf_alerts.json"),
            "host": os.path.join(demo_dir, "host_auth.log"),
            "network": os.path.join(demo_dir, "suricata_eve.json"),
        }

        total_imported = 0
        for log_type, fpath in log_files.items():
            if not os.path.isfile(fpath):
                print(f"  [SKIP] {log_type}: 文件不存在")
                continue

            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            batch = []
            for parsed in parse_log_content(content, log_type, f"demo_{log_type}"):
                log = RawLog(
                    log_type=parsed.get("log_type", log_type),
                    source=parsed.get("source", f"demo_{log_type}"),
                    event_time=parsed.get("event_time"),
                    src_ip=parsed.get("src_ip"),
                    src_port=parsed.get("src_port"),
                    dst_ip=parsed.get("dst_ip"),
                    dst_port=parsed.get("dst_port"),
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
                if len(batch) >= 200:
                    db.session.bulk_save_objects(batch)
                    db.session.flush()
                    batch.clear()

            if batch:
                db.session.bulk_save_objects(batch)
            db.session.commit()
            total_imported += len(batch) if batch else 0
            print(f"  [OK] {log_type}: 导入 {len(batch) or 'all'} 条日志")

        print(f"  -> 共导入 {total_imported} 条日志")

        # Step 3: 执行规则检测
        print("\n[3/5] 执行规则检测...")
        from app.services.rule_engine_service import run_detection

        log_types = ["web", "login", "waf", "host", "network"]
        total_alerts = 0
        for lt in log_types:
            result = run_detection(log_type=lt)
            total_alerts += result["alert_count"]
            print(f"  [DETECT] {lt}: 扫描 {result['checked_count']} 条日志, 生成 {result['alert_count']} 条告警")

        print(f"  -> 共生成 {total_alerts} 条告警")

        # Step 4: 生成攻击链
        print("\n[4/5] 生成攻击链...")
        from app.services.attack_chain_service import generate_attack_chain

        chain = generate_attack_chain()
        if chain.get("chain_id"):
            print(f"  [OK] 攻击链已生成: ID={chain['chain_id']}, 阶段数={chain['stage_count']}, 置信度={chain['confidence']}")
        else:
            print("  [INFO] 尚无足够告警生成攻击链")

        # Step 5: 资产发现
        print("\n[5/5] 资产发现...")
        try:
            from app.services.asset_service import discover_assets
            discover_assets()
            print("  [OK] 资产发现完成")
        except Exception as e:
            print(f"  [SKIP] 资产发现跳过: {e}")

        print("\n" + "=" * 60)
        print("演示数据导入完成！")
        print("=" * 60)
        print("\n启动服务: python app.py")
        print("访问地址: http://localhost:5000")
        print("默认账号: admin / admin123\n")


if __name__ == "__main__":
    main()
