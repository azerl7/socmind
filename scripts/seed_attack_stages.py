#!/usr/bin/env python3
"""攻击阶段字典种子数据（被 init_db.py 调用，也可独立运行）"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.attack_chain import AttackStage


STAGES = [
    # Web 攻击链
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
    # MITRE ATT&CK
    {"stage_code": "reconnaissance", "stage_name": "Reconnaissance 侦察", "stage_order": 1,
     "framework": "mitre_attack",
     "description": "攻击者收集目标信息，便于后续攻击"},
    {"stage_code": "initial_access", "stage_name": "Initial Access 初始访问", "stage_order": 2,
     "framework": "mitre_attack",
     "description": "攻击者尝试进入目标系统"},
    {"stage_code": "execution", "stage_name": "Execution 执行", "stage_order": 3, "framework": "mitre_attack",
     "description": "攻击者在目标系统上执行恶意代码"},
    {"stage_code": "persistence", "stage_name": "Persistence 持久化", "stage_order": 4, "framework": "mitre_attack",
     "description": "攻击者维持对目标系统的访问"},
    {"stage_code": "privilege_escalation", "stage_name": "Privilege Escalation 权限提升", "stage_order": 5,
     "framework": "mitre_attack",
     "description": "攻击者试图获得更高权限"},
    {"stage_code": "defense_evasion", "stage_name": "Defense Evasion 防御规避", "stage_order": 6,
     "framework": "mitre_attack",
     "description": "攻击者规避安全检测"},
    {"stage_code": "credential_access", "stage_name": "Credential Access 凭据访问", "stage_order": 7,
     "framework": "mitre_attack",
     "description": "攻击者获取账号凭据"},
    {"stage_code": "lateral_movement", "stage_name": "Lateral Movement 横向移动", "stage_order": 8,
     "framework": "mitre_attack",
     "description": "攻击者在内部网络横向扩展"},
    {"stage_code": "collection", "stage_name": "Collection 收集", "stage_order": 9, "framework": "mitre_attack",
     "description": "攻击者收集目标系统中的敏感数据"},
    {"stage_code": "exfiltration", "stage_name": "Exfiltration 数据外传", "stage_order": 10,
     "framework": "mitre_attack",
     "description": "攻击者将数据传出目标系统"},
]


def seed_attack_stages():
    app = create_app("development")
    with app.app_context():
        count = 0
        for stage in STAGES:
            existing = AttackStage.query.filter_by(stage_code=stage["stage_code"]).first()
            if not existing:
                db.session.add(AttackStage(**stage))
                count += 1
        db.session.commit()
        print(f"[OK] 已添加 {count} 个攻击阶段")


if __name__ == "__main__":
    seed_attack_stages()
