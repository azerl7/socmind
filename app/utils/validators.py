"""输入校验工具"""
import os

ALLOWED_EXTENSIONS = {"csv", "json", "txt", "log", "gz"}
LOG_TYPES = {"web", "login", "waf", "host", "network"}
SEVERITY_LEVELS = {"low", "medium", "high", "critical"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_log_type(log_type: str) -> bool:
    return log_type.lower() in LOG_TYPES


def validate_severity(severity: str) -> bool:
    return severity.lower() in SEVERITY_LEVELS
