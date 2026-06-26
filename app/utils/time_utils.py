"""时间处理工具"""
from datetime import datetime, timezone


def get_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                     "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return None


def format_datetime(dt: datetime | None, fmt="%Y-%m-%d %H:%M:%S") -> str | None:
    if dt is None:
        return None
    return dt.strftime(fmt)
