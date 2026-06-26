"""RAG 知识库模型"""
from datetime import datetime, timezone
from sqlalchemy import Text
import re
from app import db


class KnowledgeChunk(db.Model):
    """RAG 知识片段"""
    __tablename__ = "knowledge_chunks"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    doc_id = db.Column(db.Integer, db.ForeignKey("knowledge_docs.id", ondelete="CASCADE"),
                       nullable=False, index=True)
    chunk_index = db.Column(db.Integer, nullable=False, comment="片段序号")
    content = db.Column(db.Text, nullable=False)
    keywords = db.Column(db.String(512), nullable=True, comment="关键词")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (db.Index("idx_chunk_doc", "doc_id", "chunk_index"),)
    doc = db.relationship("KnowledgeDoc", backref="chunks", lazy="joined")

    def to_dict(self):
        return {
            "id": self.id, "doc_id": self.doc_id,
            "chunk_index": self.chunk_index, "content": self.content[:200],
            "keywords": self.keywords,
        }


def chunk_document(content: str, chunk_size: int = 500) -> list:
    """将文档按段落+大小切分为片段，提取关键词"""
    # 按段落分割
    paragraphs = re.split(r'\n\s*\n', content.strip())
    chunks = []
    current = ""
    idx = 0

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if len(current) + len(para) < chunk_size:
            current += para + "\n"
        else:
            if current:
                chunks.append(current.strip())
            current = para + "\n"
        idx += 1
    if current:
        chunks.append(current.strip())

    # 提取关键词（简单的词频）
    result = []
    for i, chunk in enumerate(chunks):
        words = re.findall(r'[\w一-鿿]+', chunk.lower())
        freq = {}
        for w in words:
            if len(w) > 1:
                freq[w] = freq.get(w, 0) + 1
        top_kws = sorted(freq.items(), key=lambda x: -x[1])[:10]
        keywords = ",".join(w for w, c in top_kws if c > 1)
        result.append({
            "chunk_index": i,
            "content": chunk,
            "keywords": keywords[:256],
        })

    return result


class KnowledgeDoc(db.Model):
    __tablename__ = "knowledge_docs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    doc_type = db.Column(db.String(64), nullable=False, index=True,
                         comment="attack/vuln/response/policy")
    source = db.Column(db.String(255), nullable=True)
    content = db.Column(Text, nullable=False)
    enabled = db.Column(db.SmallInteger, default=1, comment="1启用 0禁用")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "doc_type": self.doc_type,
            "source": self.source,
            "content": self.content[:500] + "..." if self.content and len(self.content) > 500 else self.content,
            "enabled": bool(self.enabled),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
