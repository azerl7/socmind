"""规则引擎测试"""
import pytest
import re
from app.services.rule_engine_service import (
    _match_regex, load_rules, invalidate_rule_cache,
)
from app.services.attack_chain_service import RULE_STAGE_MAP
from app.models.rule import DetectionRule
from app.models.log import RawLog
from tests.conftest import SAMPLE_NGINX_LINE


# 测试用的正则规则
def _make_rule(rule_code, pattern, attack_type="SQL Injection", severity="high"):
    return DetectionRule(
        rule_code=rule_code,
        rule_name=f"Test {rule_code}",
        category="web",
        attack_type=attack_type,
        severity=severity,
        rule_pattern=pattern,
        enabled=1,
    )


def _make_log(url="", ua="", raw="", log_type="web"):
    return RawLog(
        log_type=log_type,
        url=url,
        user_agent=ua,
        raw_content=raw,
    )


class TestRegexMatching:
    def test_sqli_detection(self):
        rule = _make_rule("TEST_SQLI", r"(?i)(union\s+select|or\s+1=1|sleep\s*\()")
        log = _make_log(url="/search?q=1 UNION SELECT 1--")
        result = _match_regex(rule, log)
        assert result is not None
        assert "matched_field" in result

    def test_xss_detection(self):
        rule = _make_rule("TEST_XSS", r"(?i)(<script|alert\(|onerror=)")
        log = _make_log(url="/search?q=<script>alert('xss')</script>")
        result = _match_regex(rule, log)
        assert result is not None

    def test_path_traversal(self):
        rule = _make_rule("TEST_PATH", r"(\.\./|\.\.\\)")
        log = _make_log(url="/download?file=../../../etc/passwd")
        result = _match_regex(rule, log)
        assert result is not None

    def test_command_injection(self):
        rule = _make_rule("TEST_RCE", r"(?i)(;\s*(ls|id|whoami)|`\w+`|\$\()")
        log = _make_log(url="/ping?host=127.0.0.1;id")
        result = _match_regex(rule, log)
        assert result is not None

    def test_no_match(self):
        rule = _make_rule("TEST_NO", r"(?i)(union\s+select)")
        log = _make_log(url="/index.html")
        result = _match_regex(rule, log)
        assert result is None

    def test_empty_pattern(self):
        rule = _make_rule("TEST_EMPTY", "")
        log = _make_log(url="/search?q=1")
        result = _match_regex(rule, log)
        assert result is None


class TestStageMapping:
    def test_sqli_maps_to_exploit(self):
        assert RULE_STAGE_MAP.get("WEB_SQLI_001") == "exploit_attempt"

    def test_brute_force_maps_to_abnormal_login(self):
        assert RULE_STAGE_MAP.get("ACC_BRUTE_001") == "abnormal_login"

    def test_scanning_maps_to_recon(self):
        assert RULE_STAGE_MAP.get("WEB_SCAN_001") == "recon"


class TestRuleCache:
    def test_cache_invalidation(self, app):
        invalidate_rule_cache()
        rules = load_rules("web")
        assert isinstance(rules, list)
