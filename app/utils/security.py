"""编号生成与安全工具"""
from datetime import datetime, timezone


def _generate_no(prefix: str) -> str:
    import secrets
    import uuid
    """生成永不重复的编号:uuid4 前 8 位 + secrets 4 位 + 日期"""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y%m%d")
    # uuid4 8 位(十六进制) + secrets 4 位(数字) = 12 位随机空间
    rand_uuid = uuid.uuid4().hex[:8]      # 例如: "3f2504e0"
    rand_sec = secrets.randbelow(10000)   # 例如: 4291
    return f"{prefix}-{date_str}-{rand_uuid}{rand_sec:04d}"


def generate_alert_no() -> str:
    return _generate_no("ALERT")


def generate_event_no() -> str:
    return _generate_no("EVENT")


def generate_chain_no() -> str:
    return _generate_no("CHAIN")


def generate_report_no() -> str:
    return _generate_no("REPORT")
