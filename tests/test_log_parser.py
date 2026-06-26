"""日志解析器测试"""
import json
import pytest
from app.services.log_parser_service import (
    parse_nginx_log, parse_login_csv_row, parse_waf_json_entry,
    parse_log_content,
)
from tests.conftest import SAMPLE_NGINX_LINE, SAMPLE_LOGIN_CSV, SAMPLE_WAF_JSON


class TestNginxParser:
    def test_parse_valid_line(self):
        result = parse_nginx_log(SAMPLE_NGINX_LINE)
        assert result is not None
        assert result["log_type"] == "web"
        assert result["src_ip"] == "192.168.1.100"
        assert result["http_method"] == "GET"
        assert "UNION%20SELECT" in result["url"]
        assert result["status_code"] == 200
        assert "sqlmap" in result["user_agent"]

    def test_parse_normal_line(self):
        line = '10.0.0.1 - - [08/May/2026:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 500'
        result = parse_nginx_log(line)
        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["url"] == "/index.html"

    def test_parse_empty_line(self):
        assert parse_nginx_log("") is None

    def test_parse_malformed_line(self):
        assert parse_nginx_log("this is not a valid log line") is None


class TestLoginParser:
    def test_parse_success_row(self):
        row = {"time": "2026-05-08 10:00:00", "src_ip": "10.0.0.1",
               "username": "admin", "action": "login", "result": "success"}
        result = parse_login_csv_row(row)
        assert result is not None
        assert result["log_type"] == "login"
        assert result["username"] == "admin"
        assert result["result"] == "success"

    def test_parse_fail_row(self):
        row = {"time": "2026-05-08 10:00:00", "src_ip": "10.0.0.1",
               "username": "admin", "action": "login", "result": "fail"}
        result = parse_login_csv_row(row)
        assert result["result"] == "fail"

    def test_parse_missing_time(self):
        row = {"src_ip": "10.0.0.1", "username": "admin", "result": "success"}
        result = parse_login_csv_row(row)
        assert result is not None
        assert result["event_time"] is None


class TestWafParser:
    def test_parse_valid_entry(self):
        entry = {"timestamp": "2026-05-08T10:12:00", "src_ip": "10.0.0.1",
                 "attack_type": "SQL Injection", "severity": "high",
                 "action": "block", "url": "/search"}
        result = parse_waf_json_entry(entry)
        assert result is not None
        assert result["log_type"] == "waf"
        assert result["src_ip"] == "10.0.0.1"
        assert result["parsed_json"]["attack_type"] == "SQL Injection"

    def test_parse_empty_entry(self):
        result = parse_waf_json_entry({})
        assert result is not None


class TestBatchParse:
    def test_parse_web_batch(self):
        content = f"{SAMPLE_NGINX_LINE}\n{SAMPLE_NGINX_LINE}\n"
        results = list(parse_log_content(content, "web"))
        assert len(results) == 2
        assert all(r["log_type"] == "web" for r in results)

    def test_parse_login_batch(self):
        results = list(parse_log_content(SAMPLE_LOGIN_CSV, "login"))
        assert len(results) == 5
        assert results[0]["result"] == "fail"
        assert results[4]["result"] == "success"

    def test_parse_waf_batch(self):
        results = list(parse_log_content(SAMPLE_WAF_JSON, "waf"))
        assert len(results) == 1
        assert results[0]["log_type"] == "waf"

    def test_parse_empty_content(self):
        results = list(parse_log_content("", "web"))
        assert len(results) == 0
