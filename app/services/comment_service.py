"""告警评论服务"""
from datetime import datetime, timezone
from app import db
from app.models.comment import AlertComment


def add_comment(alert_id: int, user_id: int, username: str,
                content: str, comment_type: str = "comment",
                old_status: str | None = None,
                new_status: str | None = None) -> AlertComment:
    """添加评论"""
    comment = AlertComment(
        alert_id=alert_id,
        user_id=user_id,
        username=username,
        content=content,
        comment_type=comment_type,
        old_status=old_status,
        new_status=new_status,
    )
    db.session.add(comment)
    db.session.commit()
    return comment


def get_comments(alert_id: int) -> list:
    """获取告警的所有评论"""
    comments = AlertComment.query.filter_by(alert_id=alert_id)\
        .order_by(AlertComment.created_at.asc()).all()
    return [c.to_dict() for c in comments]


def delete_comment(comment_id: int, user_id: int) -> bool:
    """删除评论（仅作者可删除）"""
    comment = db.session.get(AlertComment, comment_id)
    if not comment or comment.user_id != user_id:
        return False
    db.session.delete(comment)
    db.session.commit()
    return True
