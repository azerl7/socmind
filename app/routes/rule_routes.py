"""规则接口 — 接入 rule_engine_service"""
from flask import Blueprint, request, jsonify
from app import db
from app.models.rule import DetectionRule
from app.services.rule_engine_service import load_rules, run_detection, invalidate_rule_cache
from flask_login import login_required
from app.utils.response import success_response, error_response, paginated_response

rule_bp = Blueprint("rule_routes", __name__)


@rule_bp.route("", methods=["GET"])
def list_rules():
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    category = request.args.get("category")
    enabled = request.args.get("enabled")

    query = DetectionRule.query
    if category:
        query = query.filter_by(category=category)
    if enabled is not None:
        query = query.filter_by(enabled=int(enabled))

    pagination = query.order_by(DetectionRule.id).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify(paginated_response(
        [r.to_dict() for r in pagination.items],
        page, page_size, pagination.total
    ))


@rule_bp.route("", methods=["POST"])
def create_rule():
    data = request.get_json() or {}
    required = ["rule_code", "rule_name", "category", "attack_type", "severity"]
    for field in required:
        if field not in data:
            return jsonify(error_response(40001, f"缺少必填字段: {field}")), 400

    existing = DetectionRule.query.filter_by(rule_code=data["rule_code"]).first()
    if existing:
        return jsonify(error_response(40001, f"规则编码已存在: {data['rule_code']}")), 400

    rule = DetectionRule(
        rule_code=data["rule_code"],
        rule_name=data["rule_name"],
        category=data["category"],
        attack_type=data["attack_type"],
        severity=data["severity"],
        rule_pattern=data.get("rule_pattern", ""),
        rule_config=data.get("rule_config"),
        stage_code=data.get("stage_code", ""),
        enabled=data.get("enabled", 1),
        description=data.get("description", ""),
    )
    db.session.add(rule)
    db.session.commit()
    invalidate_rule_cache()

    return jsonify(success_response({"id": rule.id})), 201


@rule_bp.route("/<int:rule_id>", methods=["GET"])
def get_rule(rule_id):
    rule = db.session.get(DetectionRule, rule_id)
    if not rule:
        return jsonify(error_response(40401, "规则不存在")), 404
    return jsonify(success_response(rule.to_dict()))


@rule_bp.route("/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    rule = db.session.get(DetectionRule, rule_id)
    if not rule:
        return jsonify(error_response(40401, "规则不存在")), 404

    data = request.get_json() or {}
    for field in ["rule_name", "category", "attack_type", "severity",
                   "rule_pattern", "stage_code", "description"]:
        if field in data:
            setattr(rule, field, data[field])
    if "enabled" in data:
        rule.enabled = 1 if data["enabled"] else 0
    if "rule_config" in data:
        rule.rule_config = data["rule_config"]

    db.session.commit()
    invalidate_rule_cache()
    return jsonify(success_response(rule.to_dict()))


@rule_bp.route("/<int:rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    """启用/禁用规则"""
    rule = db.session.get(DetectionRule, rule_id)
    if not rule:
        return jsonify(error_response(40401, "规则不存在")), 404

    rule.enabled = 0 if rule.enabled else 1
    db.session.commit()
    invalidate_rule_cache()
    return jsonify(success_response({"id": rule.id, "enabled": bool(rule.enabled)}))


@rule_bp.route("/run", methods=["POST"])
def run_rules():
    """执行规则检测"""
    data = request.get_json() or {}
    log_type = data.get("log_type")
    rule_ids = data.get("rule_ids")
    start_time = data.get("start_time")
    end_time = data.get("end_time")

    try:
        result = run_detection(
            log_type=log_type,
            rule_ids=rule_ids,
            start_time=start_time,
            end_time=end_time,
        )
        return jsonify(success_response({
            "checked_count": result["checked_count"],
            "alert_count": result["alert_count"],
        }))
    except Exception as e:
        return jsonify(error_response(50001, f"规则检测失败: {str(e)}")), 500


@rule_bp.route("/export", methods=["GET"])
def export_rules():
    """导出所有规则为 JSON"""
    from flask import Response
    rules = DetectionRule.query.order_by(DetectionRule.id).all()
    data = [r.to_dict() for r in rules]
    return Response(
        json.dumps(data, ensure_ascii=False, indent=2),
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=socmind_rules.json"},
    )


@rule_bp.route("/import", methods=["POST"])
def import_rules():
    """从 JSON 导入规则"""
    import json
    file = request.files.get("file")
    if not file:
        # 支持 JSON body
        data = request.get_json()
        if not data:
            return jsonify(error_response(40001, "请上传规则文件或提供 JSON 数据")), 400
        rules_data = data if isinstance(data, list) else [data]
    else:
        try:
            content = file.read().decode("utf-8")
            rules_data = json.loads(content)
            if not isinstance(rules_data, list):
                rules_data = [rules_data]
        except Exception as e:
            return jsonify(error_response(40001, f"文件解析失败: {e}")), 400

    imported = 0
    skipped = 0
    errors = []

    for rule_data in rules_data:
        try:
            rule_code = rule_data.get("rule_code", "")
            if not rule_code:
                errors.append("缺少 rule_code，跳过")
                skipped += 1
                continue

            existing = DetectionRule.query.filter_by(rule_code=rule_code).first()
            if existing:
                # 已有规则则更新
                for field in ["rule_name", "category", "attack_type", "severity",
                               "rule_pattern", "stage_code", "description"]:
                    if field in rule_data:
                        setattr(existing, field, rule_data[field])
                if "enabled" in rule_data:
                    existing.enabled = 1 if rule_data["enabled"] else 0
                if "rule_config" in rule_data:
                    existing.rule_config = rule_data["rule_config"]
                imported += 1
            else:
                rule = DetectionRule(
                    rule_code=rule_code,
                    rule_name=rule_data.get("rule_name", rule_code),
                    category=rule_data.get("category", "web"),
                    attack_type=rule_data.get("attack_type", "Unknown"),
                    severity=rule_data.get("severity", "medium"),
                    rule_pattern=rule_data.get("rule_pattern", ""),
                    rule_config=rule_data.get("rule_config"),
                    stage_code=rule_data.get("stage_code", ""),
                    enabled=rule_data.get("enabled", 1),
                    description=rule_data.get("description", ""),
                )
                db.session.add(rule)
                imported += 1
        except Exception as e:
            errors.append(f"{rule_data.get('rule_code', 'unknown')}: {e}")
            skipped += 1

    db.session.commit()
    invalidate_rule_cache()

    return jsonify(success_response({
        "imported": imported,
        "skipped": skipped,
        "errors": errors[:10],
    }))


@rule_bp.route("/test", methods=["POST"])
@login_required
def test_rule():
    """规则测试工具：输入测试文本，验证规则命中情况"""
    import re
    data = request.get_json() or {}
    sample = data.get("sample", "")
    rule_id = data.get("rule_id")

    if not sample:
        return jsonify(error_response(40001, "请提供测试样本")), 400

    results = []

    if rule_id:
        rules = [db.session.get(DetectionRule, rule_id)]
        if not rules[0]:
            return jsonify(error_response(40401, "规则不存在")), 404
    else:
        rules = DetectionRule.query.filter(
            DetectionRule.enabled == 1,
            DetectionRule.rule_pattern.isnot(None),
            DetectionRule.rule_pattern != "",
        ).all()

    for rule in rules:
        try:
            pattern = re.compile(rule.rule_pattern)
            matches = pattern.findall(sample)
            if matches:
                results.append({
                    "rule_id": rule.id,
                    "rule_code": rule.rule_code,
                    "rule_name": rule.rule_name,
                    "attack_type": rule.attack_type,
                    "severity": rule.severity,
                    "matched": True,
                    "match_count": len(matches),
                    "match_preview": str(matches[0])[:200] if matches else "",
                })
        except re.error as e:
            results.append({
                "rule_id": rule.id,
                "rule_code": rule.rule_code,
                "rule_name": rule.rule_name,
                "matched": False,
                "error": f"正则错误: {e}",
            })

    # 也检查统计类规则（显示但不测试）
    if not rule_id:
        stat_rules = DetectionRule.query.filter(
            DetectionRule.enabled == 1,
            (DetectionRule.rule_pattern == "") | (DetectionRule.rule_pattern.is_(None)),
        ).all()
        for rule in stat_rules:
            results.append({
                "rule_id": rule.id,
                "rule_code": rule.rule_code,
                "rule_name": rule.rule_name,
                "attack_type": rule.attack_type,
                "matched": None,
                "note": "统计类规则，需在真实日志上执行检测",
            })

    return jsonify(success_response({
        "sample": sample[:200],
        "sample_length": len(sample),
        "tested_rules": len(rules),
        "results": results,
    }))
