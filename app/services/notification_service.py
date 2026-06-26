"""通知集成服务：邮件告警、Webhook（企业微信/钉钉/飞书/通用）"""
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from app import db
from app.models.alert import Alert
from app.models.config import SystemConfig
from app.utils.time_utils import format_datetime

logger = logging.getLogger(__name__)


def _get_config(key: str, default: str = "") -> str:
    config = SystemConfig.query.filter_by(config_key=key).first()
    return config.config_value if config and config.config_value else default


# ── 通知状态跟踪 ──
_notified_alerts: set = set()


def _format_alert_message(alert: Alert) -> dict:
    """格式化告警为通知消息"""
    time_str = format_datetime(alert.event_time) or "未知"
    severity_icons = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢",
    }
    icon = severity_icons.get(alert.severity, "⚪")

    text = f"""[{icon} SOCMind 安全告警]
━━━━━━━━━━━━━━━━━━
等级：{alert.severity.upper()}
类型：{alert.attack_type}
标题：{alert.title}
源IP：{alert.src_ip or '未知'}
目标：{alert.dst_ip or alert.asset or '未知'}
时间：{time_str}
风险分：{alert.risk_score}/100
状态：{alert.status}
━━━━━━━━━━━━━━━━━━
查看详情：http://localhost:5000/alerts/{alert.id}"""

    return {
        "title": f"[{alert.severity.upper()}] {alert.attack_type} - {alert.title}",
        "text": text,
        "severity": alert.severity,
        "alert_id": alert.id,
    }


# ── 通用 Webhook ──

def send_webhook(url: str, message: dict) -> bool:
    """发送通用 Webhook JSON POST"""
    try:
        data = json.dumps(message).encode("utf-8")
        req = Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        resp = urlopen(req, timeout=10)
        logger.info(f"Webhook 发送成功: {resp.status}")
        return True
    except URLError as e:
        logger.error(f"Webhook 发送失败: {e}")
        return False
    except Exception as e:
        logger.error(f"Webhook 异常: {e}")
        return False


# ── 企业微信 Bot ──

def send_wechat_work(webhook_url: str, message: dict) -> bool:
    """发送企业微信机器人消息"""
    payload = {
        "msgtype": "markdown",
        "markdown": {
            "content": message["text"].replace("━━", "---"),
        },
    }
    return send_webhook(webhook_url, payload)


# ── 钉钉 Bot ──

def send_dingtalk(webhook_url: str, message: dict) -> bool:
    """发送钉钉机器人消息"""
    payload = {
        "msgtype": "text",
        "text": {
            "content": message["text"],
        },
    }
    return send_webhook(webhook_url, payload)


# ── 飞书 Bot ──

def send_feishu(webhook_url: str, message: dict) -> bool:
    """发送飞书机器人消息"""
    severity_colors = {
        "critical": "red", "high": "orange",
        "medium": "yellow", "low": "green",
    }
    payload = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": message["title"]},
                "template": severity_colors.get(message["severity"], "blue"),
            },
            "elements": [
                {"tag": "markdown", "content": message["text"]},
            ],
        },
    }
    return send_webhook(webhook_url, payload)


# ── 邮件通知 ──

def send_email(smtp_host: str, smtp_port: int, username: str, password: str,
               to_addr: str, message: dict) -> bool:
    """发送邮件告警"""
    try:
        msg = MIMEText(message["text"], "plain", "utf-8")
        msg["Subject"] = Header(message["title"], "utf-8")
        msg["From"] = username
        msg["To"] = to_addr

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
        server.starttls()
        server.login(username, password)
        server.sendmail(username, [to_addr], msg.as_string())
        server.quit()
        logger.info(f"邮件通知发送成功: {to_addr}")
        return True
    except Exception as e:
        logger.error(f"邮件通知发送失败: {e}")
        return False


# ── 主通知入口 ──

def notify_alert(alert_id: int, force: bool = False) -> dict:
    """根据告警触发通知

    Args:
        alert_id: 告警 ID
        force: 是否强制发送（忽略去重）

    Returns:
        {"sent": bool, "channels": [str], "errors": [str]}
    """
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return {"sent": False, "channels": [], "errors": ["告警不存在"]}

    # 去重：同告警只通知一次
    if alert_id in _notified_alerts and not force:
        return {"sent": False, "channels": [], "errors": [], "skipped": "duplicate"}

    channels = []
    errors = []
    message = _format_alert_message(alert)

    # 检查是否启用通知
    enabled = _get_config("notification_enabled", "false")
    if enabled != "true":
        return {"sent": False, "channels": [], "errors": [], "skipped": "notifications disabled"}

    # 只通知 high/critical 级别
    min_severity = _get_config("notification_min_severity", "high")
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if severity_order.get(alert.severity, 0) < severity_order.get(min_severity, 2):
        return {"sent": False, "channels": [], "errors": [], "skipped": f"severity too low ({alert.severity} < {min_severity})"}

    # ── 邮件 ──
    smtp_host = _get_config("smtp_host")
    smtp_port = int(_get_config("smtp_port", "587"))
    smtp_user = _get_config("smtp_username")
    smtp_pass = _get_config("smtp_password")
    mail_to = _get_config("notification_email_to")

    if smtp_host and smtp_user and smtp_pass and mail_to:
        if send_email(smtp_host, smtp_port, smtp_user, smtp_pass, mail_to, message):
            channels.append("email")
        else:
            errors.append("email")

    # ── Webhook ──
    webhook_url = _get_config("webhook_url")
    webhook_type = _get_config("webhook_type", "generic")

    if webhook_url:
        sender_map = {
            "generic": send_webhook,
            "wechat": send_wechat_work,
            "dingtalk": send_dingtalk,
            "feishu": send_feishu,
        }
        sender = sender_map.get(webhook_type, send_webhook)
        if sender(webhook_url, message):
            channels.append(f"webhook({webhook_type})")
        else:
            errors.append(f"webhook({webhook_type})")

    if channels:
        _notified_alerts.add(alert_id)

    return {
        "sent": len(channels) > 0,
        "channels": channels,
        "errors": errors,
    }


def test_notification(channel: str = "webhook") -> dict:
    """发送测试通知"""
    test_msg = {
        "title": "[TEST] SOCMind 通知测试",
        "text": "这是一条来自 SOCMind 的测试通知\n\n如果收到此消息，说明通知配置正确。",
        "severity": "low",
        "alert_id": 0,
    }

    if channel == "email":
        smtp_host = _get_config("smtp_host")
        smtp_port = int(_get_config("smtp_port", "587"))
        smtp_user = _get_config("smtp_username")
        smtp_pass = _get_config("smtp_password")
        mail_to = _get_config("notification_email_to")
        if not all([smtp_host, smtp_user, smtp_pass, mail_to]):
            return {"success": False, "message": "邮件配置不完整"}
        ok = send_email(smtp_host, smtp_port, smtp_user, smtp_pass, mail_to, test_msg)
        return {"success": ok, "message": "邮件发送成功" if ok else "邮件发送失败"}

    webhook_url = _get_config("webhook_url")
    webhook_type = _get_config("webhook_type", "generic")
    if not webhook_url:
        return {"success": False, "message": "Webhook URL 未配置"}

    sender_map = {
        "generic": send_webhook,
        "wechat": send_wechat_work,
        "dingtalk": send_dingtalk,
        "feishu": send_feishu,
    }
    sender = sender_map.get(webhook_type, send_webhook)
    ok = sender(webhook_url, test_msg)
    return {"success": ok, "message": f"{webhook_type} 通知发送成功" if ok else f"{webhook_type} 通知发送失败"}


def notify_report_ready(report_id: int, report_title: str) -> dict:
    """通知报告就绪"""
    channels = []
    errors = []

    message = {
        "title": f"[REPORT] SOCMind 安全报告已生成",
        "text": f"新报告已生成：{report_title}\n\n查看详情：http://localhost:5000/reports/{report_id}",
        "severity": "low",
        "alert_id": 0,
    }

    smtp_host = _get_config("smtp_host")
    smtp_port = int(_get_config("smtp_port", "587"))
    smtp_user = _get_config("smtp_username")
    smtp_pass = _get_config("smtp_password")
    mail_to = _get_config("notification_email_to")

    if smtp_host and smtp_user and smtp_pass and mail_to:
        if send_email(smtp_host, smtp_port, smtp_user, smtp_pass, mail_to, message):
            channels.append("email")
        else:
            errors.append("email")

    webhook_url = _get_config("webhook_url")
    webhook_type = _get_config("webhook_type", "generic")
    if webhook_url:
        sender_map = {
            "generic": send_webhook,
            "wechat": send_wechat_work,
            "dingtalk": send_dingtalk,
            "feishu": send_feishu,
        }
        sender = sender_map.get(webhook_type, send_webhook)
        if sender(webhook_url, message):
            channels.append(f"webhook({webhook_type})")
        else:
            errors.append(f"webhook({webhook_type})")

    return {"sent": len(channels) > 0, "channels": channels, "errors": errors}
