"""知识库管理接口"""
import os
from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models.knowledge import KnowledgeDoc
from app.utils.response import success_response, error_response, paginated_response

knowledge_bp = Blueprint("knowledge_routes", __name__)


@knowledge_bp.route("", methods=["GET"])
def list_knowledge():
    """查询知识库列表"""
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    doc_type = request.args.get("doc_type")
    keyword = request.args.get("keyword")

    query = KnowledgeDoc.query
    if doc_type:
        query = query.filter_by(doc_type=doc_type)
    if keyword:
        query = query.filter(KnowledgeDoc.title.contains(keyword) | KnowledgeDoc.content.contains(keyword))

    pagination = query.order_by(KnowledgeDoc.created_at.desc()).paginate(
        page=page, per_page=page_size, error_out=False
    )
    return jsonify(paginated_response(
        [k.to_dict() for k in pagination.items],
        page, page_size, pagination.total
    ))


@knowledge_bp.route("/<int:doc_id>", methods=["GET"])
def get_knowledge(doc_id):
    doc = db.session.get(KnowledgeDoc, doc_id)
    if not doc:
        return jsonify(error_response(40401, "知识文档不存在")), 404
    d = doc.to_dict()
    d["content"] = doc.content  # 完整内容
    return jsonify(success_response(d))


@knowledge_bp.route("", methods=["POST"])
def create_knowledge():
    """创建知识文档"""
    data = request.get_json() or {}
    title = data.get("title", "").strip()
    doc_type = data.get("doc_type", "attack")
    content = data.get("content", "")

    if not title or not content:
        return jsonify(error_response(40001, "标题和内容不能为空")), 400

    doc = KnowledgeDoc(
        title=title,
        doc_type=doc_type,
        source=data.get("source", "manual"),
        content=content,
        enabled=1,
    )
    db.session.add(doc)
    db.session.commit()
    return jsonify(success_response({"id": doc.id})), 201


@knowledge_bp.route("/<int:doc_id>", methods=["PUT"])
def update_knowledge(doc_id):
    doc = db.session.get(KnowledgeDoc, doc_id)
    if not doc:
        return jsonify(error_response(40401, "知识文档不存在")), 404
    data = request.get_json() or {}
    for field in ("title", "doc_type", "content", "source", "enabled"):
        if field in data:
            setattr(doc, field, data[field])
    db.session.commit()
    return jsonify(success_response({"id": doc.id}))


@knowledge_bp.route("/<int:doc_id>", methods=["DELETE"])
def delete_knowledge(doc_id):
    doc = db.session.get(KnowledgeDoc, doc_id)
    if not doc:
        return jsonify(error_response(40401, "知识文档不存在")), 404
    db.session.delete(doc)
    db.session.commit()
    return jsonify(success_response({"id": doc_id}))


@knowledge_bp.route("/load-files", methods=["POST"])
def load_knowledge_files():
    """从 knowledge_base 目录加载 Markdown 文件到数据库"""
    from app.services.rag_service import _load_knowledge_base_files
    _load_knowledge_base_files()
    count = KnowledgeDoc.query.count()
    return jsonify(success_response({"total": count, "message": f"共 {count} 条知识文档"}))


@knowledge_bp.route("/search", methods=["GET"])
def search_knowledge():
    """搜索知识库"""
    from app.services.rag_service import search_knowledge
    q = request.args.get("q", "")
    limit = request.args.get("limit", 3, type=int)
    if not q:
        return jsonify(error_response(40001, "搜索关键词不能为空")), 400
    result = search_knowledge(q, limit=limit)
    return jsonify(success_response({"content": result, "keyword": q}))
