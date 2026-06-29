"""告警接口 — 接入 alert_service + risk_score_service"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.alert import Alert, AlertEvidence
from app.models.alert import AlertEvent, EventAlertRelation
from app.services.alert_service import (
    query_alerts, get_alert_detail, update_alert_status,
    batch_update_status, get_alert_trend, aggregate_alerts,
    deduplicate_alerts,
)
from app.services.risk_score_service import recalculate_alert_score
from app.services.audit_service import record_audit
from app.utils.response import success_response, error_response, paginated_response

alert_bp = Blueprint("alert_routes", __name__)


@alert_bp.route("", methods=["GET"])
def list_alerts():
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    severity = request.args.get("severity")
    status = request.args.get("status")
    attack_type = request.args.get("attack_type")
    src_ip = request.args.get("src_ip")
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    result = query_alerts(
        page=page, page_size=page_size,
        severity=severity, status=status,
        attack_type=attack_type, src_ip=src_ip,
        start_time=start_time, end_time=end_time,
    )
    return jsonify(paginated_response(
        result["items"], result["page"], result["page_size"], result["total"]
    ))


@alert_bp.route("/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    detail = get_alert_detail(alert_id)
    if not detail:
        return jsonify(error_response(40401, "告警不存在")), 404
    return jsonify(success_response(detail))


@alert_bp.route("/<int:alert_id>/status", methods=["PATCH"])
@login_required
def update_status(alert_id):
    data = request.get_json() or {}
    new_status = data.get("status", "")
    comment = data.get("comment", "")

    # 改状态前先读出旧状态(用于审计 detail)
    old_alert = db.session.get(Alert, alert_id)
    old_status = old_alert.status if old_alert else None

    if not update_alert_status(
        alert_id, new_status, comment,
        user_id=current_user.id, username=current_user.username,
    ):
        return jsonify(error_response(40001, "状态更新失败，请检查状态值")), 400

    alert = db.session.get(Alert, alert_id)

    # 记录审计日志(后端统一记录,不依赖前端调用)
    record_audit(
        action="alert_status_changed",
        target_type="alert",
        target_id=alert_id,
        detail={
            "from": old_status,
            "to": new_status,
            "comment": comment,
            # 附告警关键信息,审计日志一眼能看出是关于哪条告警的
            "alert_no": alert.alert_no,
            "title": alert.title,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "src_ip": alert.src_ip,
        },
    )

    return jsonify(success_response({"id": alert.id, "status": alert.status}))


@alert_bp.route("/batch-status", methods=["POST"])
def batch_status():
    """批量更新告警状态"""
    data = request.get_json() or {}
    alert_ids = data.get("alert_ids", [])
    new_status = data.get("status", "")

    count = batch_update_status(alert_ids, new_status)
    return jsonify(success_response({"updated_count": count}))


@alert_bp.route("/recalculate-score/<int:alert_id>", methods=["POST"])
def recalculate_score(alert_id):
    """重新计算风险分"""
    score = recalculate_alert_score(alert_id)
    return jsonify(success_response({"alert_id": alert_id, "risk_score": score}))


@alert_bp.route("/aggregate", methods=["POST"])
def aggregate():
    """告警聚合为事件"""
    data = request.get_json() or {}
    src_ip = data.get("src_ip")
    asset = data.get("asset")
    time_window = data.get("time_window_minutes")

    event = aggregate_alerts(src_ip=src_ip, asset=asset, time_window_minutes=time_window)
    if not event:
        return jsonify(success_response({"message": "没有符合条件的告警进行聚合", "event_id": None}))

    return jsonify(success_response({
        "event_id": event.id,
        "event_no": event.event_no,
        "title": event.title,
        "alert_count": EventAlertRelation.query.filter_by(event_id=event.id).count(),
    }))


@alert_bp.route("/deduplicate", methods=["POST"])
def deduplicate():
    """告警去重"""
    time_window = request.args.get("time_window_minutes", 5, type=int)
    deleted = deduplicate_alerts(time_window_minutes=time_window)
    return jsonify(success_response({"deleted_count": deleted}))


@alert_bp.route("/trend", methods=["GET"])
def trend():
    """告警趋势统计"""
    days = request.args.get("days", 7, type=int)
    data = get_alert_trend(days=days)
    return jsonify(success_response(data))


@alert_bp.route("/events", methods=["GET"])
def list_events():
    """查询聚合事件列表（含告警数）"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    pagination = AlertEvent.query.order_by(AlertEvent.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    from sqlalchemy import func
    items = []
    for e in pagination.items:
        d = e.to_dict()
        d["alert_count"] = EventAlertRelation.query.filter_by(event_id=e.id).count()
        items.append(d)
    return jsonify(paginated_response(
        items, page, page_size, pagination.total
    ))


@alert_bp.route("/events/<int:event_id>", methods=["GET"])
def get_event(event_id):
    """查询事件详情（含关联告警）"""
    event = db.session.get(AlertEvent, event_id)
    if not event:
        return jsonify(error_response(40401, "事件不存在")), 404
    detail = event.to_dict()

    relations = EventAlertRelation.query.filter_by(event_id=event_id).all()
    alert_ids = [r.alert_id for r in relations]
    alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all()
    detail["alerts"] = [a.to_dict() for a in alerts]
    return jsonify(success_response(detail))


# ── 告警标签 ──

@alert_bp.route("/tags", methods=["GET"])
def list_tags():
    """查询所有标签"""
    from app.models.alert import AlertTag
    tags = AlertTag.query.all()
    return jsonify(success_response([t.to_dict() for t in tags]))


@alert_bp.route("/tags", methods=["POST"])
def create_tag():
    """创建标签"""
    from app.models.alert import AlertTag
    data = request.get_json() or {}
    tag_name = data.get("tag_name", "").strip()
    if not tag_name:
        return jsonify(error_response(40001, "标签名不能为空")), 400
    existing = AlertTag.query.filter_by(tag_name=tag_name).first()
    if existing:
        return jsonify(error_response(40001, "标签已存在")), 400
    tag = AlertTag(tag_name=tag_name, tag_color=data.get("tag_color", "primary"))
    db.session.add(tag)
    db.session.commit()
    return jsonify(success_response(tag.to_dict())), 201


@alert_bp.route("/tags/<int:tag_id>", methods=["DELETE"])
def delete_tag(tag_id):
    """删除标签"""
    from app.models.alert import AlertTag, AlertTagRelation
    tag = db.session.get(AlertTag, tag_id)
    if not tag:
        return jsonify(error_response(40401, "标签不存在")), 404
    AlertTagRelation.query.filter_by(tag_id=tag_id).delete()
    db.session.delete(tag)
    db.session.commit()
    return jsonify(success_response({"id": tag_id}))


@alert_bp.route("/<int:alert_id>/tags", methods=["GET"])
def get_alert_tags(alert_id):
    """查询告警的标签"""
    from app.models.alert import AlertTag, AlertTagRelation
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify(error_response(40401, "告警不存在")), 404
    relations = AlertTagRelation.query.filter_by(alert_id=alert_id).all()
    tag_ids = [r.tag_id for r in relations]
    tags = AlertTag.query.filter(AlertTag.id.in_(tag_ids)).all() if tag_ids else []
    return jsonify(success_response([t.to_dict() for t in tags]))


@alert_bp.route("/<int:alert_id>/tags", methods=["POST"])
def add_alert_tag(alert_id):
    """给告警添加标签"""
    from app.models.alert import AlertTag, AlertTagRelation
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify(error_response(40401, "告警不存在")), 404
    data = request.get_json() or {}
    tag_id = data.get("tag_id")
    tag_name = data.get("tag_name", "").strip()
    if tag_id:
        tag = db.session.get(AlertTag, tag_id)
    elif tag_name:
        tag = AlertTag.query.filter_by(tag_name=tag_name).first()
        if not tag:
            tag = AlertTag(tag_name=tag_name)
            db.session.add(tag)
            db.session.flush()
    else:
        return jsonify(error_response(40001, "请提供 tag_id 或 tag_name")), 400
    if not tag:
        return jsonify(error_response(40401, "标签不存在")), 404
    existing = AlertTagRelation.query.filter_by(alert_id=alert_id, tag_id=tag.id).first()
    if not existing:
        db.session.add(AlertTagRelation(alert_id=alert_id, tag_id=tag.id))
        db.session.commit()
    return jsonify(success_response({"tag_id": tag.id, "tag_name": tag.tag_name}))


@alert_bp.route("/<int:alert_id>/tags/<int:tag_id>", methods=["DELETE"])
def remove_alert_tag(alert_id, tag_id):
    """移除告警的标签"""
    from app.models.alert import AlertTagRelation
    relation = AlertTagRelation.query.filter_by(alert_id=alert_id, tag_id=tag_id).first()
    if not relation:
        return jsonify(error_response(40401, "标签关联不存在")), 404
    db.session.delete(relation)
    db.session.commit()
    return jsonify(success_response({"deleted": True}))


@alert_bp.route("/<int:alert_id>/assign", methods=["POST"])
@login_required
def assign_alert(alert_id):
    """分配告警给分析员"""
    from app.models.user import User
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify(error_response(40401, "告警不存在")), 404
    data = request.get_json() or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify(error_response(40001, "请指定用户ID")), 400
    user = db.session.get(User, user_id)
    if not user:
        return jsonify(error_response(40401, "用户不存在")), 404
    old_assignee = alert.assigned_username
    alert.assigned_to = user.id
    alert.assigned_username = user.username
    db.session.commit()
    try:
        from app.services.comment_service import add_comment
        add_comment(alert_id=alert.id, user_id=current_user.id,
                    username=current_user.username,
                    content=f"告警分配: {old_assignee or '未分配'} → {user.username}",
                    comment_type="assignment")
    except Exception:
        pass
    return jsonify(success_response({"assigned_to": user.id, "assigned_username": user.username}))
