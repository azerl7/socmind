# 集中导出所有模型，方便 db.create_all() 自动发现
from app.models.user import User, Role, UserRole
from app.models.log import RawLog, LogImportTask
from app.models.rule import DetectionRule
from app.models.alert import Alert, AlertEvidence, AlertEvent, EventAlertRelation, AlertTag, AlertTagRelation
from app.models.attack_chain import AttackStage, AttackChain, AttackChainNode
from app.models.ai_analysis import AIAnalysis
from app.models.knowledge import KnowledgeDoc
from app.models.knowledge import KnowledgeChunk
from app.models.report import Report, ReportTemplate
from app.models.config import SystemConfig, AuditLog, AICallLog
from app.models.asset import Asset, AssetRelation
from app.models.suppression import AlertSuppression
from app.models.comment import AlertComment
from app.models.login_log import LoginLog
from app.models.user_pref import UserPreference

__all__ = [
    "User", "Role", "UserRole",
    "RawLog", "LogImportTask",
    "DetectionRule",
    "Alert", "AlertEvidence", "AlertEvent", "EventAlertRelation", "AlertTag", "AlertTagRelation",
    "AttackStage", "AttackChain", "AttackChainNode",
    "AIAnalysis",
    "KnowledgeDoc",
    "KnowledgeChunk",
    "Report", "ReportTemplate",
    "SystemConfig", "AuditLog", "AICallLog",
    "Asset", "AssetRelation",
    "AlertSuppression",
    "AlertComment",
    "LoginLog",
    "UserPreference",
]
