"""用户管理接口"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.user import User, Role, UserRole
from app.utils.response import success_response, error_response, paginated_response

user_bp = Blueprint("user_routes", __name__)


@user_bp.route("", methods=["GET"])
def list_users():
    """查询用户列表（含角色）"""
    users = User.query.order_by(User.id).all()
    return jsonify(success_response([u.to_dict() for u in users]))


@user_bp.route("/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify(error_response(40401, "用户不存在")), 404
    return jsonify(success_response(user.to_dict()))


@user_bp.route("", methods=["POST"])
def create_user():
    """创建用户"""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    nickname = data.get("nickname", username)
    email = data.get("email", "")
    role_codes = data.get("roles", ["viewer"])

    if not username or not password:
        return jsonify(error_response(40001, "用户名和密码不能为空")), 400

    # 密码强度验证
    from app.utils.password_policy import validate_password
    pw_check = validate_password(password)
    if not pw_check["valid"]:
        return jsonify(error_response(40001, pw_check["message"])), 400

    if User.query.filter_by(username=username).first():
        return jsonify(error_response(40001, "用户名已存在")), 400

    user = User(
        username=username,
        nickname=nickname,
        email=email,
        status=1,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.flush()

    # 分配角色
    for code in role_codes:
        role = Role.query.filter_by(role_code=code).first()
        if role:
            db.session.add(UserRole(user_id=user.id, role_id=role.id))

    db.session.commit()
    return jsonify(success_response(user.to_dict())), 201


@user_bp.route("/<int:user_id>/toggle-status", methods=["POST"])
def toggle_user_status(user_id):
    """启用/禁用用户"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify(error_response(40401, "用户不存在")), 404
    user.status = 0 if user.status else 1
    db.session.commit()
    return jsonify(success_response({"id": user.id, "status": user.status}))


@user_bp.route("/<int:user_id>/reset-password", methods=["POST"])
def reset_password(user_id):
    """重置用户密码"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify(error_response(40401, "用户不存在")), 404
    data = request.get_json() or {}
    new_password = data.get("password", "")
    if not new_password:
        return jsonify(error_response(40001, "密码不能为空")), 400
    from app.utils.password_policy import validate_password
    pw_check = validate_password(new_password)
    if not pw_check["valid"]:
        return jsonify(error_response(40001, pw_check["message"])), 400
    user.set_password(new_password)
    db.session.commit()
    return jsonify(success_response({"id": user.id, "message": "密码已重置"}))


@user_bp.route("/preferences", methods=["GET"])
@login_required
def get_preferences():
    """获取当前用户偏好"""
    from app.models.user_pref import UserPreference
    prefs = UserPreference.query.filter_by(user_id=current_user.id).all()
    return jsonify(success_response({p.pref_key: p.pref_value for p in prefs}))


@user_bp.route("/preferences", methods=["PUT"])
@login_required
def update_preferences():
    """更新用户偏好"""
    from app.models.user_pref import UserPreference
    data = request.get_json() or {}
    for key, value in data.items():
        pref = UserPreference.query.filter_by(
            user_id=current_user.id, pref_key=key
        ).first()
        if pref:
            pref.pref_value = str(value)
        else:
            pref = UserPreference(
                user_id=current_user.id,
                pref_key=key,
                pref_value=str(value),
            )
            db.session.add(pref)
    db.session.commit()
    return jsonify(success_response({"message": "偏好已保存"}))


@user_bp.route("/roles", methods=["GET"])
def list_roles():
    """查询角色列表"""
    roles = Role.query.all()
    return jsonify(success_response([r.to_dict() for r in roles]))
