"""密码策略工具"""
import re


PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128


def validate_password(password: str) -> dict:
    """验证密码强度

    Returns:
        {"valid": bool, "message": str, "score": int}
    """
    if not password:
        return {"valid": False, "message": "密码不能为空", "score": 0}

    if len(password) < PASSWORD_MIN_LENGTH:
        return {
            "valid": False,
            "message": f"密码长度不能少于 {PASSWORD_MIN_LENGTH} 位",
            "score": 0,
        }

    if len(password) > PASSWORD_MAX_LENGTH:
        return {
            "valid": False,
            "message": f"密码长度不能超过 {PASSWORD_MAX_LENGTH} 位",
            "score": 0,
        }

    score = 0
    checks = []

    # 长度评分
    if len(password) >= 12:
        score += 25
        checks.append("长度充足")
    elif len(password) >= 8:
        score += 15
        checks.append("长度合格")

    # 包含数字
    if re.search(r"\d", password):
        score += 15
        checks.append("包含数字")

    # 包含小写字母
    if re.search(r"[a-z]", password):
        score += 15
        checks.append("包含小写字母")

    # 包含大写字母
    if re.search(r"[A-Z]", password):
        score += 20
        checks.append("包含大写字母")

    # 包含特殊字符
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
        score += 25
        checks.append("包含特殊字符")

    # 判定强度
    if score < 30:
        valid = False
        message = "密码强度不足: " + "、".join(
            missing for missing in [
                "需要数字" if not re.search(r"\d", password) else "",
                "需要大写字母" if not re.search(r"[A-Z]", password) else "",
                "需要特殊字符" if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password) else "",
            ] if missing
        )
    else:
        valid = True
        if score >= 75:
            message = "强密码"
        elif score >= 50:
            message = "中等密码"
        else:
            message = "弱密码（建议增加复杂度）"

    return {"valid": valid, "message": message, "score": score}
