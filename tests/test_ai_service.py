"""AI 研判服务测试"""
import pytest
from app.services.ai_service import (
    _build_single_alert_prompt, _fallback_analysis, _parse_json_result,
)
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.models.log import RawLog
from app.utils.security import generate_alert_no


def _make_test_alert(attack_type="SQL Injection", severity="high"):
    rule = DetectionRule(
        rule_code="TEST",
        rule_name="Test Rule",
        category="web",
        attack_type=attack_type,
        severity=severity,
        description="Test description",
    )
    log = RawLog(
        log_type="web",
        url="/search?q=test",
        raw_content="GET /search?q=1 UNION SELECT 1",
    )
    alert = Alert(
        alert_no=generate_alert_no(),
        title=f"Test {attack_type}",
        rule_id=1,
        raw_log_id=1,
        attack_type=attack_type,
        severity=severity,
        risk_score=75,
        status="new",
    )
    alert.id = 999  # 测试用模拟 ID
    alert.rule = rule
    alert.raw_log = log
    return alert


class TestPromptTemplate:
    def test_build_prompt_contains_alert_info(self, app):
        alert = _make_test_alert()
        prompt = _build_single_alert_prompt(alert)
        assert "SQL Injection" in prompt
        assert "high" in prompt
        assert "summary" in prompt
        assert "risk_level" in prompt
        assert "suggestion" in prompt

    def test_prompt_requests_json(self, app):
        alert = _make_test_alert()
        prompt = _build_single_alert_prompt(alert)
        assert "{" in prompt
        assert "}" in prompt


class TestFallback:
    def test_fallback_returns_required_fields(self, app):
        alert = _make_test_alert("Brute Force", "high")
        result = _fallback_analysis(alert, error="API timeout")
        assert "analysis_id" in result
        assert result["risk_level"] == "high"
        assert result["suggestion"] is not None
        assert "technical_steps" in result
        assert len(result["technical_steps"]) > 0
        assert result.get("_fallback") is True

    def test_fallback_includes_error_info(self, app):
        alert = _make_test_alert()
        result = _fallback_analysis(alert, error="Connection refused")
        assert "Connection refused" in str(result.get("_error", ""))


class TestJsonParsing:
    def test_parse_valid_json(self):
        json_str = '{"summary": "Test", "risk_level": "high"}'
        result = _parse_json_result(json_str)
        assert result.get("summary") == "Test"
        assert result.get("risk_level") == "high"

    def test_parse_json_in_code_block(self):
        json_str = '```json\n{"summary": "In block"}\n```'
        result = _parse_json_result(json_str)
        assert result.get("summary") == "In block"

    def test_parse_invalid_text(self):
        result = _parse_json_result("Just some text")
        assert "raw_text" in result
