---
name: project-socmind
description: SOCMind AI 安全运营研判平台项目概况、技术栈和关键文件
type: project
---

# SOCMind 项目概况

## 项目定位
AI 安全告警研判与攻击链还原系统，面向企业 SOC 场景。核心流程：多源日志 → 规则检测 → 告警聚合 → AI 研判 → 攻击链还原 → 报告输出。

## 技术栈
- **后端**: Python 3 + Flask + SQLAlchemy + MySQL
- **前端**: Jinja2 模板 + Bootstrap 5 + ECharts
- **AI**: OpenAI API + RAG 安全知识库
- **部署**: Docker + Docker Compose

## 关键文件和结构
- `SOCMind_AI安全告警研判与攻击链还原系统_详细任务书.md` - 项目完整任务书
- `app/__init__.py` - Flask 应用工厂
- `app/models/` - 15+ ORM 模型（user, log, alert, rule, attack_chain, ai_analysis, report, config 等）
- `app/routes/` - 21 个路由蓝图（覆盖 auth, log, rule, alert, ai, chain, report, config, dashboard, user, system, knowledge 等）
- `app/services/` - 19 个业务服务（log_parser, rule_engine, alert, ai, rag, attack_chain, report, asset 等）
- `app/templates/` - 25 个 HTML 页面模板
- `scripts/init_db.py` - 数据库初始化（建表 + 种子数据 + 知识库）
- `scripts/import_demo_data.py` - 一键导入演示数据
- `scripts/generate_demo_logs.py` - 生成模拟日志
- `tests/` - 测试用例（conftest + 5 个测试模块）
- `docs/` - 数据库设计、API 设计、部署、演示指南文档
- `Dockerfile` + `docker-compose.yml` - 容器化部署

## 默认账号
admin / admin123

## 开发注意事项
- 数据库使用 MySQL 8.0（root/1@socmind）
- AI 功能依赖 OpenAI API（通过系统配置表管理 Key）
- RAG 知识库使用本地 Markdown/JSON 文件 + 关键词检索
- 测试使用 SQLite 内存数据库
- 所有响应使用统一 JSON 格式（code/message/data）
