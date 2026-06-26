"""SOCMind 系统配置"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """应用基础配置"""
    SECRET_KEY = os.environ.get("SECRET_KEY", "socmind-secret-key-change-in-production")

    # MySQL 数据库配置 — root密码为1
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///socmind.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {}   # SQLite 不需要 pool

    # JWT / Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    JWT_EXPIRATION_HOURS = 8

    # 文件上传
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.path.join(basedir, "uploads")
    ALLOWED_EXTENSIONS = {"csv", "json", "txt", "log", "gz"}

    # OpenAI 配置（通过系统配置表管理）
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")
    OPENAI_TIMEOUT = 30

    # 系统默认配置
    DEFAULT_BRUTE_FORCE_THRESHOLD = 5       # 同 IP 登录失败 N 次触发
    DEFAULT_TIME_WINDOW_MINUTES = 10        # 告警聚合时间窗口（分钟）
    DEFAULT_HIGH_FREQ_THRESHOLD = 100       # 单位时间请求次数阈值
    DEFAULT_HIGH_FREQ_WINDOW_SECONDS = 60   # 高频检测时间窗口（秒）

    # 日志解析配置
    LOG_PAGE_SIZE_DEFAULT = 20
    LOG_PAGE_SIZE_MAX = 200


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///socmind.db"
    )


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
