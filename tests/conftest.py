"""pytest 测试配置与夹具"""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db as _db
from app.models import *  # noqa: F401, F403


@pytest.fixture(scope="module")
def app():
    """每个测试模块创建独立的 SQLite 临时数据库"""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    app = create_app("testing")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    ctx = app.app_context()
    ctx.push()
    _db.create_all()
    yield app
    _db.drop_all()
    ctx.pop()
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """测试客户端"""
    return app.test_client()


# ── 测试样本数据 ──

SAMPLE_NGINX_LINE = '192.168.1.100 - - [08/May/2026:10:12:00 +0000] "GET /search?q=1%27%20UNION%20SELECT%20*%20FROM%20users-- HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0 (compatible; sqlmap/1.7)"'

SAMPLE_LOGIN_CSV = """time,src_ip,username,action,result
2026-05-08 10:00:00,192.168.1.100,admin,login,fail
2026-05-08 10:00:05,192.168.1.100,admin,login,fail
2026-05-08 10:00:10,192.168.1.100,admin,login,fail
2026-05-08 10:00:15,192.168.1.100,root,login,fail
2026-05-08 10:00:20,192.168.1.100,admin,login,success"""

SAMPLE_WAF_JSON = """[
    {"timestamp":"2026-05-08T10:12:00","src_ip":"192.168.1.100","dst_ip":"10.0.0.5","rule_id":"WAF-001","attack_type":"SQL Injection","action":"block","url":"/search?q=1 UNION SELECT","severity":"high","request_method":"GET","user_agent":"sqlmap"}
]"""
