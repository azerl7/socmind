"""定时任务服务：周期报告生成、数据清理等后台作业"""
import logging
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app import db

logger = logging.getLogger(__name__)

# 全局调度器实例
_scheduler: BackgroundScheduler | None = None


def init_scheduler(app):
    """初始化后台调度器"""
    global _scheduler
    if _scheduler is not None:
        return

    _scheduler = BackgroundScheduler()
    _scheduler._logger = logging.getLogger("apscheduler")

    # 注册定时报告任务（在应用上下文中执行）
    def daily_report_job():
        with app.app_context():
            _generate_periodic_report("daily")

    def weekly_report_job():
        with app.app_context():
            _generate_periodic_report("weekly")

    def monthly_report_job():
        with app.app_context():
            _generate_periodic_report("monthly")

    def escalation_check_job():
        with app.app_context():
            from app.services.escalation_service import check_escalations
            check_escalations()

    def data_retention_job():
        with app.app_context():
            from app.services.retention_service import purge_old_data
            purge_old_data()

    # 读取配置决定是否启用定时报告
    with app.app_context():
        try:
            from app.models.config import SystemConfig

            daily_enabled = SystemConfig.query.filter_by(
                config_key="scheduler_daily_report", config_value="true"
            ).first()
            weekly_enabled = SystemConfig.query.filter_by(
                config_key="scheduler_weekly_report", config_value="true"
            ).first()
            monthly_enabled = SystemConfig.query.filter_by(
                config_key="scheduler_monthly_report", config_value="true"
            ).first()

            daily_time = "0 9 * * *"  # 每天 9:00
            weekly_time = "0 9 * * 1"  # 每周一 9:00
            monthly_time = "0 9 1 * *"  # 每月1日 9:00

            daily_cfg = SystemConfig.query.filter_by(config_key="scheduler_daily_cron").first()
            if daily_cfg and daily_cfg.config_value:
                daily_time = daily_cfg.config_value

            weekly_cfg = SystemConfig.query.filter_by(config_key="scheduler_weekly_cron").first()
            if weekly_cfg and weekly_cfg.config_value:
                weekly_time = weekly_cfg.config_value

            monthly_cfg = SystemConfig.query.filter_by(config_key="scheduler_monthly_cron").first()
            if monthly_cfg and monthly_cfg.config_value:
                monthly_time = monthly_cfg.config_value

            if daily_enabled:
                _scheduler.add_job(daily_report_job, CronTrigger.from_crontab(daily_time),
                                    id="daily_report", replace_existing=True,
                                    name="每日报告生成")
            if weekly_enabled:
                _scheduler.add_job(weekly_report_job, CronTrigger.from_crontab(weekly_time),
                                    id="weekly_report", replace_existing=True,
                                    name="每周报告生成")
            if monthly_enabled:
                _scheduler.add_job(monthly_report_job, CronTrigger.from_crontab(monthly_time),
                                    id="monthly_report", replace_existing=True,
                                    name="每月报告生成")

            # 告警升级检查（每15分钟）
            _scheduler.add_job(escalation_check_job, CronTrigger.from_crontab("*/15 * * * *"),
                                id="escalation_check", replace_existing=True,
                                name="告警升级检查")

            # 数据清理（每天凌晨 3:00）
            _scheduler.add_job(data_retention_job, CronTrigger.from_crontab("0 3 * * *"),
                                id="data_retention", replace_existing=True,
                                name="数据保留清理")

        except Exception as e:
            logger.warning(f"调度器初始化配置读取失败: {e}")

    _scheduler.start()
    logger.info("后台调度器已启动")


def shutdown_scheduler():
    """关闭调度器"""
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("后台调度器已关闭")


def _generate_periodic_report(period: str):
    """生成周期报告

    period: daily / weekly / monthly
    """
    from app.models.alert import Alert
    from app.models.attack_chain import AttackChain
    from app.services.report_service import generate_report

    now = datetime.now(timezone.utc)

    # 根据周期计算时间窗口
    if period == "daily":
        from datetime import timedelta
        window_start = now - timedelta(days=1)
        title_suffix = "日报"
    elif period == "weekly":
        from datetime import timedelta
        window_start = now - timedelta(days=7)
        title_suffix = "周报"
    elif period == "monthly":
        from datetime import timedelta
        window_start = now - timedelta(days=30)
        title_suffix = "月报"
    else:
        return {"status": "error", "message": f"Unknown period: {period}"}

    # 统计本期告警
    alert_count = Alert.query.filter(
        Alert.event_time >= window_start,
    ).count()

    alert_by_severity = {
        "critical": Alert.query.filter(
            Alert.event_time >= window_start, Alert.severity == "critical"
        ).count(),
        "high": Alert.query.filter(
            Alert.event_time >= window_start, Alert.severity == "high"
        ).count(),
        "medium": Alert.query.filter(
            Alert.event_time >= window_start, Alert.severity == "medium"
        ).count(),
        "low": Alert.query.filter(
            Alert.event_time >= window_start, Alert.severity == "low"
        ).count(),
    }

    chain_count = AttackChain.query.filter(
        AttackChain.created_at >= window_start,
    ).count()

    if alert_count == 0:
        logger.info(f"[自动报告] {period} 无告警，跳过生成")
        return {"status": "skipped", "reason": "no_alerts"}

    # 生成报告
    title = f"SOCMind 安全运营{title_suffix} - {now.strftime('%Y-%m-%d')}"
    summary = (
        f"## {title}\n\n"
        f"**报告周期**: {window_start.strftime('%Y-%m-%d %H:%M')} ~ {now.strftime('%Y-%m-%d %H:%M')}\n\n"
        f"### 本期概览\n\n"
        f"- 告警总数: {alert_count}\n"
        f"  - 严重: {alert_by_severity['critical']} | "
        f"高危: {alert_by_severity['high']} | "
        f"中危: {alert_by_severity['medium']} | "
        f"低危: {alert_by_severity['low']}\n"
        f"- 攻击链: {chain_count} 条\n\n"
        f"*自动生成于 {now.strftime('%Y-%m-%d %H:%M:%S UTC')}*"
    )

    result = generate_report(
        title=title,
        content=summary,
        alert_ids=None,
        chain_ids=None,
        template_id=None,
        created_by="system",
    )

    report_id = result.get("report_id")
    logger.info(f"[自动报告] {period} 报告已生成 (ID: {report_id}), 共 {alert_count} 条告警")

    # 推送通知
    try:
        from app.services.notification_service import notify_report_ready
        notify_report_ready(report_id, title)
    except Exception as e:
        logger.warning(f"[自动报告] 通知推送失败: {e}")

    return {"status": "generated", "report_id": report_id, "alert_count": alert_count}


def get_scheduler_status() -> dict:
    """获取调度器状态"""
    global _scheduler
    if _scheduler is None:
        return {"running": False, "jobs": []}

    jobs = []
    for job in _scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger),
        })

    return {
        "running": _scheduler.running,
        "jobs": jobs,
    }


def add_scheduled_job(job_id: str, cron_expr: str, job_name: str = "") -> bool:
    """添加或更新定时任务"""
    global _scheduler
    if _scheduler is None:
        return False

    job_map = {
        "daily_report": lambda: _generate_periodic_report("daily"),
        "weekly_report": lambda: _generate_periodic_report("weekly"),
        "monthly_report": lambda: _generate_periodic_report("monthly"),
    }

    if job_id not in job_map:
        return False

    _scheduler.add_job(
        job_map[job_id],
        CronTrigger.from_crontab(cron_expr),
        id=job_id,
        replace_existing=True,
        name=job_name or job_id,
    )
    return True


def remove_scheduled_job(job_id: str) -> bool:
    """移除定时任务"""
    global _scheduler
    if _scheduler is None:
        return False
    try:
        _scheduler.remove_job(job_id)
        return True
    except Exception:
        return False
