# SOCMind - AI 安全运营研判平台

SOCMind 是一个面向企业安全运营场景的 **AI 安全告警研判与攻击链还原系统**。系统通过接入多源安全日志，利用规则引擎进行告警检测，再结合 RAG 安全知识库与大模型 API 完成告警解释、风险研判、攻击链还原和报告生成。
推广连接：[Orcaouter](https://www.orcarouter.ai/ref/ref_ec70461a6c6083b1f589)

## 核心流程

```
多源日志 → 规则检测 → 告警聚合 → AI 研判 → 攻击链还原 → 报告输出
```

## 技术栈

| 层级 | 技术选型 |
|---|---|
| 后端 | Python 3 + Flask |
| 数据库 | SQLite(默认) / MySQL 8.0 + SQLAlchemy |
| 前端 | Jinja2 模板 + Bootstrap 5 + ECharts |
| AI | OpenAI API + RAG 安全知识库 |
| 部署 | Docker + Docker Compose |

## 快速启动

### 方式一：本地运行（SQLite，开箱即用）

```bash
# 1. 复制环境变量样板
cp .env.example .env

# 2. 安装依赖
pip install -r requirements.txt

# 3. 初始化数据库（SQLite 文件会自动创建）
python scripts/init_db.py

# 4. 生成演示日志
python scripts/generate_demo_logs.py

# 5. 启动服务
python app.py
```

### 方式二：本地运行（MySQL）

```bash
# 1. 创建数据库
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS socmind DEFAULT CHARACTER SET utf8mb4;"

# 2. 编辑 .env,设置
#    DATABASE_URL=mysql+pymysql://user:password@localhost:3306/socmind?charset=utf8mb4

# 3. 后续步骤同方式一
```

### 方式二：Docker 部署

```bash
docker compose up -d
```

### 访问系统

打开浏览器访问 http://localhost:5000

- **默认账号**: admin / admin123

## 功能模块

| 模块 | 功能说明 |
|---|---|
| 仪表盘 | 系统概览、告警趋势图、风险评分、统计卡片 |
| 告警中心 | 告警列表/详情、状态流转、AI研判、批量操作 |
| 安全事件 | 告警聚合、事件详情、一键生成攻击链 |
| 日志中心 | 日志文件上传、多格式解析、多条件检索 |
| 攻击链 | 告警→阶段映射、时间线图谱、AI摘要、报告生成 |
| 报告中心 | 安全报告生成、HTML 下载、打印/PDF |
| 规则管理 | 检测规则列表、启用/禁用、一键执行检测 |
| 安全知识库 | 知识文档管理、RAG检索测试、文件加载 |
| 系统管理 | AI 配置、阈值配置、一键导入演示数据、健康检查 |
| 审计日志 | 操作审计记录查询 |
| 用户管理 | 用户列表、创建、启用/禁用 |
| API 文档 | 完整 REST API 参考 |

## 系统架构

```
┌────────────────────────────────────────────┐
│                前端展示层                   │
│ 仪表盘 / 日志中心 / 告警中心 / 攻击链 / 报告 │
└─────────────────────┬──────────────────────┘
                      │
┌─────────────────────▼──────────────────────┐
│              Flask 后端服务层               │
│ 用户认证 / 业务 API / 权限控制 / 配置管理    │
└──────────┬──────────┬──────────┬────────────┘
           │          │          │
┌──────────▼───┐ ┌────▼─────┐ ┌──▼───────────┐
│ 日志解析模块 │ │ 规则引擎 │ │ AI 研判模块  │
└──────────┬───┘ └────┬─────┘ └──┬───────────┘
           │          │          │
┌──────────▼──────────▼──────────▼────────────┐
│              SQLite / MySQL 数据层            │
│ 用户 / 日志 / 告警 / 规则 / 攻击链 / 报告     │
└──────────┬──────────────────────┬────────────┘
           │                      │
┌──────────▼──────────┐ ┌─────────▼──────────┐
│   RAG 安全知识库     │ │  OpenAI API 服务    │
│ ATT&CK / CVE / 手册  │ │ 研判 / 解释 / 生成  │
└─────────────────────┘ └────────────────────┘
```

## API 概述

统一前缀: `/api/v1`

| 分组 | 主要接口 |
|---|---|
| Auth | POST login, GET/POST logout |
| Logs | POST import, GET list, POST parse |
| Rules | GET list, POST create, POST run |
| Alerts | GET list/detail, PATCH status, POST aggregate |
| AI | POST analyze alert/chain, GET analyses |
| Attack Chains | POST generate, GET list/detail |
| Reports | POST generate, GET list/detail |
| Knowledge | GET/POST/PUT/DELETE docs, GET search |
| Users | GET/POST, POST toggle-status |
| System | GET health, POST demo/import, GET audit-logs |

详细 API 文档访问 `/api-docs` 页面。

## 演示数据

系统内置三个演示场景：

1. **Web 攻击链还原** — 扫描探测 → 敏感路径 → SQL注入 → XSS → 路径穿越
2. **账号暴力破解与异常登录** — 同 IP 批量登录失败 → 暴力破解告警
3. **综合安全事件复盘** — 多源日志关联分析

在「系统管理」页点击「一键导入演示数据」即可体验完整流程。

## 项目结构

```
socmind/
├── app.py                 # 应用入口
├── config.py              # 配置
├── requirements.txt       # Python 依赖
├── Dockerfile             # Docker 构建
├── docker-compose.yml     # 一键部署
├── README.md              # 本文件
├── app/
│   ├── models/            # 20 张数据表 ORM 模型
│   ├── routes/            # 8 组 API + 页面路由
│   ├── services/          # 8 个业务服务
│   ├── templates/         # 16 个页面模板
│   └── static/            # CSS/JS 资源
├── scripts/               # 初始化与演示脚本
├── knowledge_base/        # RAG 安全知识库
├── tests/                 # 测试用例
├── uploads/               # 上传日志存储
└── demo_data/             # 生成的演示日志
```

## 演示流程（5分钟）

1. 登录系统（admin / admin123）
2. 打开「系统管理」→ 点击「一键导入演示数据」
3. 打开「告警中心」查看检测到的告警
4. 点击告警 →「AI研判」查看分析结果
5. 打开「攻击链」→ 填写源IP →「生成攻击链」
6. 攻击链详情页查看时间线图谱
7. 点击「生成报告」→ 查看/下载安全报告
