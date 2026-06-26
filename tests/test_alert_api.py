"""告警 API 测试"""
import pytest
from app import db as _db
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.models.log import RawLog
from app.utils.security import generate_alert_no


@pytest.fixture
def sample_rule(app):
    rule = DetectionRule(
        rule_code="TEST_API",
        rule_name="Test Rule",
        category="web",
        attack_type="SQL Injection",
        severity="high",
        rule_pattern=r"(?i)(union\s+select)",
        enabled=1,
    )
    _db.session.add(rule)
    _db.session.commit()
    yield rule
    _db.session.delete(rule)
    _db.session.commit()


@pytest.fixture
def sample_log(app):
    log = RawLog(
        log_type="web",
        src_ip="10.0.0.1",
        url="/search?q=test",
        raw_content="test log",
    )
    _db.session.add(log)
    _db.session.commit()
    yield log
    _db.session.delete(log)
    _db.session.commit()


class TestAlertAPI:
    def test_create_alert(self, app, sample_rule, sample_log):
        alert = Alert(
            alert_no=generate_alert_no(),
            title="Test Alert",
            rule_id=sample_rule.id,
            raw_log_id=sample_log.id,
            attack_type="SQL Injection",
            severity="high",
            risk_score=75,
            src_ip="10.0.0.1",
            status="new",
        )
        _db.session.add(alert)
        _db.session.commit()

        fetched = _db.session.get(Alert, alert.id)
        assert fetched is not None
        assert fetched.attack_type == "SQL Injection"
        assert fetched.risk_score == 75
        assert fetched.status == "new"

    def test_alert_status_flow(self, app, sample_rule, sample_log):
        alert = Alert(
            alert_no=generate_alert_no(),
            title="Status Flow Test",
            rule_id=sample_rule.id,
            raw_log_id=sample_log.id,
            attack_type="XSS",
            severity="medium",
            risk_score=50,
            status="new",
        )
        _db.session.add(alert)
        _db.session.commit()

        alert.status = "in_progress"
        _db.session.commit()
        assert _db.session.get(Alert, alert.id).status == "in_progress"

        alert.status = "confirmed"
        _db.session.commit()
        assert _db.session.get(Alert, alert.id).status == "confirmed"

        alert.status = "closed"
        _db.session.commit()
        assert _db.session.get(Alert, alert.id).status == "closed"

    def test_risk_score_range(self):
        scores = []
        from app.services.risk_score_service import _severity_base_score
        for sev in ["low", "medium", "high", "critical"]:
            score = _severity_base_score(sev)
            assert 0 <= score <= 100
            scores.append(score)
        assert scores == sorted(scores)

    def test_alert_to_dict(self, app, sample_rule, sample_log):
        alert = Alert(
            alert_no=generate_alert_no(),
            title="Dict Test",
            rule_id=sample_rule.id,
            raw_log_id=sample_log.id,
            attack_type="SQL Injection",
            severity="high",
            risk_score=80,
            src_ip="10.0.0.1",
            status="new",
        )
        d = alert.to_dict()
        assert d["title"] == "Dict Test"
        assert d["attack_type"] == "SQL Injection"
        assert d["risk_score"] == 80
        assert "created_at" in d
