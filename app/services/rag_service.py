"""RAG 知识检索服务：基于关键词匹配的安全知识检索"""
import re
import os
from typing import List

from app import db
from app.models.knowledge import KnowledgeDoc


# 攻击类型 → 相关 doc_type 映射
ATTACK_TO_DOC_TYPE = {
    "SQL Injection": "attack",
    "XSS": "attack",
    "Path Traversal": "attack",
    "Command Injection": "attack",
    "Brute Force": "attack",
    "Scanning": "attack",
    "Sensitive Path Access": "attack",
    "Abnormal UA": "attack",
    "Abnormal Login": "attack",
    # 主机安全
    "SSH Brute Force": "attack",
    "SSH Brute Force Success": "attack",
    "Suspicious Sudo": "attack",
    "Abnormal SSH Login Time": "attack",
}

ATTACK_TO_KEYWORDS = {
    "SQL Injection": ["sql", "注入", "injection", "union", "select"],
    "XSS": ["xss", "script", "跨站", "javascript"],
    "Path Traversal": ["路径", "traversal", "目录", "../", "..\\"],
    "Command Injection": ["命令", "command", "rce", "执行", "shell"],
    "Brute Force": ["暴力", "brute", "破解", "爆破", "登录失败"],
    "Scanning": ["扫描", "scan", "探测", "高频"],
    "Sensitive Path Access": ["敏感", "sensitive", "路径", "目录"],
    # 主机安全
    "SSH Brute Force": ["ssh", "暴力", "爆破", "破解", "登录失败", "auth"],
    "SSH Brute Force Success": ["ssh", "爆破成功", "暴力破解", "入侵"],
    "Suspicious Sudo": ["sudo", "权限提升", "命令执行", "提权", "privesc"],
    "Abnormal SSH Login Time": ["ssh", "异常", "非工作时段", "凌晨登录"],
}


def _load_knowledge_base_files():
    """从 knowledge_base 目录加载知识文件到数据库"""
    from flask import current_app
    import glob as glob_mod

    base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "knowledge_base")
    if not os.path.isdir(base_dir):
        return

    doc_type_map = {
        "attack_techniques": "attack",
        "web_security": "attack",
        "host_security": "attack",
        "incident_response": "response",
        "report_templates": "policy",
    }

    for fpath in glob_mod.glob(os.path.join(base_dir, "*.md")):
        fname = os.path.splitext(os.path.basename(fpath))[0]
        doc_type = "attack"
        for key, dt in doc_type_map.items():
            if fname == key or key in fname:
                doc_type = dt
                break

        title = fname.replace("_", " ").title()

        existing = KnowledgeDoc.query.filter_by(title=title).first()
        if existing:
            continue

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            doc = KnowledgeDoc(
                title=title,
                doc_type=doc_type,
                source=fpath,
                content=content,
                enabled=1,
            )
            db.session.add(doc)
            db.session.flush()

            # 自动创建知识片段
            from app.models.knowledge import chunk_document
            chunks_data = chunk_document(content)
            for c in chunks_data:
                chunk = KnowledgeChunk(
                    doc_id=doc.id,
                    chunk_index=c["chunk_index"],
                    content=c["content"],
                    keywords=c["keywords"],
                )
                db.session.add(chunk)

            db.session.commit()
        except Exception:
            db.session.rollback()


def search_knowledge(query: str, limit: int = 3) -> str:
    """根据查询内容检索相关知识

    采用关键词匹配 + ATT&CK 映射方式（轻量级 RAG，无需向量数据库）

    Args:
        query: 攻击类型或搜索关键词
        limit: 返回的知识条目数上限

    Returns:
        拼接后的知识文本
    """
    # 确保知识库已加载
    count = KnowledgeDoc.query.count()
    if count == 0:
        _load_knowledge_base_files()

    keywords = set()
    query_lower = query.lower()

    # 根据攻击类型获取关键词
    for attack_type, kw_list in ATTACK_TO_KEYWORDS.items():
        if attack_type.lower() in query_lower or query_lower in attack_type.lower():
            keywords.update(kw_list)

    # 把查询本身也作为关键词
    keywords.add(query_lower)

    # 检索知识条目
    docs = KnowledgeDoc.query.filter_by(enabled=1).all()
    scored = []

    for doc in docs:
        doc_lower = doc.content.lower()
        score = 0
        for kw in keywords:
            if kw.lower() in doc_lower:
                score += doc_lower.count(kw.lower())
        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda x: -x[0])

    # 从知识片段中搜索（更精确）
    from app.models.knowledge import KnowledgeChunk
    chunk_results = []
    for chunk in KnowledgeChunk.query.all():
        chunk_lower = chunk.content.lower()
        score = 0
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower in chunk_lower:
                score += chunk_lower.count(kw_lower)
        if score > 0:
            chunk_results.append((score, chunk.doc.title if chunk.doc else "", chunk.content))

    if chunk_results:
        chunk_results.sort(key=lambda x: -x[0])
        results = []
        for score, title, content in chunk_results[:limit]:
            results.append(f"## {title}\n{content[:1500]}")
        return "\n\n---\n\n".join(results)

    docs = KnowledgeDoc.query.filter_by(enabled=1).limit(limit).all()
    return "\n\n---\n\n".join(
        f"## {d.title}\n{d.content[:1000]}" for d in docs
    )
