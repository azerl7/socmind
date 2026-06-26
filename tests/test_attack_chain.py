"""攻击链服务测试"""
import pytest
from app.models.attack_chain import AttackStage
from app.services.attack_chain_service import (
    RULE_STAGE_MAP, ATTACK_TYPE_STAGE_MAP, _map_alert_to_stage,
)
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.utils.security import generate_alert_no


class TestStageMapping:
    def test_rule_stage_map_has_entries(self):
        assert len(RULE_STAGE_MAP) >= 10
        assert "WEB_SQLI_001" in RULE_STAGE_MAP
        assert "ACC_BRUTE_001" in RULE_STAGE_MAP

    def test_attack_type_map_has_entries(self):
        assert "SQL Injection" in ATTACK_TYPE_STAGE_MAP
        assert "Brute Force" in ATTACK_TYPE_STAGE_MAP
        assert ATTACK_TYPE_STAGE_MAP["SQL Injection"] == "exploit_attempt"
        assert ATTACK_TYPE_STAGE_MAP["Brute Force"] == "abnormal_login"

    def test_alert_to_stage_by_attack_type(self, app):
        """通过攻击类型映射阶段（不需 DB）"""
        alert = Alert(
            alert_no=generate_alert_no(),
            title="Test",
            attack_type="SQL Injection",
            severity="high", status="new",
        )
        stage = _map_alert_to_stage(alert)
        assert stage == "exploit_attempt"

    def test_unknown_type_defaults(self, app):
        alert = Alert(
            alert_no=generate_alert_no(),
            title="Test",
            attack_type="Unknown Type",
            severity="low", status="new",
        )
        stage = _map_alert_to_stage(alert)
        assert stage == "unknown"
