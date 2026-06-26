# SOCMind API 设计文档

## 概述

- **基础路径**: `/api/v1`
- **响应格式**: JSON
- **认证方式**: Session Cookie (Flask-Login)
- **HTTP 方法**: GET（查询）、POST（创建/执行）、PUT（全量更新）、PATCH（部分更新）、DELETE（删除）

---

## 通用响应格式

### 成功响应

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

### 失败响应

```json
{
  "code": 40001,
  "message": "参数错误",
  "data": null
}
```

### 分页响应

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "items": [],
    "page": 1,
    "page_size": 20,
    "total": 100
  }
}
```

### 错误码定义

| 错误码 | 说明 |
|--------|------|
| 0 | 成功 |
| 40001 | 请求参数错误 |
| 40002 | 不支持的日志类型 |
| 40003 | 文件格式不支持 |
| 40101 | 用户名或密码错误 |
| 40102 | Token 无效或已过期 |
| 40301 | 用户已被禁用 |
| 40401 | 目标资源不存在 |
| 50001 | 服务内部错误 |
| 50002 | AI 服务配置缺失 |

---

## 1. 认证接口

### 1.1 用户登录

```
POST /api/v1/auth/login
```

**权限**: 无

**请求**:
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**成功响应**:
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "session_token",
    "user": {
      "id": 1,
      "username": "admin",
      "nickname": "管理员",
      "roles": ["admin"]
    }
  }
}
```

**错误**: `40101` 用户名或密码错误, `40301` 用户已禁用

### 1.2 用户登出

```
POST /api/v1/auth/logout
```

**权限**: 登录用户

**响应**: 标准成功响应

---

## 2. 日志接口

### 2.1 上传日志文件

```
POST /api/v1/logs/import
```

**权限**: analyst/admin

**请求 (multipart/form-data)**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| file | file | 是 | 日志文件 |
| log_type | string | 是 | web/login/waf/host/network |
| source | string | 否 | 日志来源说明 |

**成功响应**:
```json
{
  "code": 0,
  "data": {
    "task_id": 1001,
    "status": "pending"
  }
}
```

**错误**: `40001` 文件为空, `40002` 不支持的日志类型, `40003` 文件格式不支持

### 2.2 执行日志解析任务

```
POST /api/v1/logs/import/{task_id}/parse
```

**权限**: analyst/admin

**成功响应**:
```json
{
  "code": 0,
  "data": {
    "task_id": 1001,
    "total_count": 1000,
    "success_count": 985,
    "failed_count": 15
  }
}
```

### 2.3 查询原始日志

```
GET /api/v1/logs
```

**权限**: viewer/analyst/admin

**查询参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页数量，默认20 |
| log_type | string | 否 | 日志类型 (web/login/waf/host/network) |
| src_ip | string | 否 | 源 IP |
| dst_ip | string | 否 | 目标 IP |
| username | string | 否 | 账号 |
| start_time | string | 否 | 开始时间 (YYYY-MM-DD HH:mm:ss) |
| end_time | string | 否 | 结束时间 |
| keyword | string | 否 | 关键词搜索 |

**响应**: 标准分页响应

### 2.4 查询日志详情

```
GET /api/v1/logs/{log_id}
```

**权限**: viewer/analyst/admin

### 2.5 日志去重

```
POST /api/v1/logs/deduplicate
```

**权限**: admin

**请求**:
```json
{
  "log_type": "web",
  "hours": 24
}
```

**响应**:
```json
{
  "code": 0,
  "data": {
    "deleted": 12,
    "message": "已删除 12 条重复日志"
  }
}
```

### 2.6 查询导入任务列表

```
GET /api/v1/logs/import-tasks
```

**权限**: viewer/analyst/admin

---

## 3. 规则接口

### 3.1 查询规则列表

```
GET /api/v1/rules
```

**权限**: viewer/analyst/admin

**查询参数**: category, enabled, page, page_size

### 3.2 创建规则

```
POST /api/v1/rules
```

**权限**: admin

**请求**:
```json
{
  "rule_code": "WEB_SQLI_001",
  "rule_name": "SQL 注入特征检测",
  "category": "web",
  "attack_type": "SQL Injection",
  "severity": "high",
  "rule_pattern": "(?i)(union\\s+select|or\\s+1=1)",
  "stage_code": "exploit_attempt",
  "enabled": true,
  "description": "检测常见 SQL 注入请求特征"
}
```

### 3.3 查询、更新、删除规则

```
GET    /api/v1/rules/{rule_id}
PUT    /api/v1/rules/{rule_id}
```

### 3.4 启用/禁用规则

```
POST /api/v1/rules/{rule_id}/toggle
```

### 3.5 执行规则检测

```
POST /api/v1/rules/run
```

**权限**: analyst/admin

**请求**:
```json
{
  "log_type": "web",
  "start_time": "2026-05-01 00:00:00",
  "end_time": "2026-05-07 23:59:59",
  "rule_ids": [1, 2, 3]
}
```

**响应**:
```json
{
  "code": 0,
  "data": {
    "checked_count": 5000,
    "alert_count": 42
  }
}
```

### 3.6 规则测试工具 (R-11)

```
POST /api/v1/rules/test
```

**权限**: 登录用户

**请求**:
```json
{
  "sample": "/search?q=1' UNION SELECT * FROM users--",
  "rule_id": 1
}
```
> 不传 `rule_id` 则测试所有已启用的正则规则

**响应**:
```json
{
  "code": 0,
  "data": {
    "sample": "sample text",
    "tested_rules": 10,
    "results": [
      {
        "rule_id": 1,
        "rule_code": "WEB_SQLI_001",
        "rule_name": "SQL 注入特征检测",
        "matched": true,
        "match_count": 1,
        "match_preview": "union select"
      }
    ]
  }
}
```

### 3.7 导入/导出规则

```
GET  /api/v1/rules/export    → 导出全部规则为 JSON
POST /api/v1/rules/import    → 从 JSON 导入规则
```

---

## 4. 告警接口

### 4.1 查询告警列表

```
GET /api/v1/alerts
```

**权限**: viewer/analyst/admin

**查询参数**: severity, status, attack_type, src_ip, start_time, end_time, page, page_size

### 4.2 查询告警详情

```
GET /api/v1/alerts/{alert_id}
```

返回告警基本信息、命中规则、原始日志、证据列表。

### 4.3 更新告警状态

```
PATCH /api/v1/alerts/{alert_id}/status
```

**权限**: analyst/admin

**请求**:
```json
{
  "status": "confirmed",
  "comment": "经研判为真实攻击"
}
```

可选状态: `new`, `in_progress`, `confirmed`, `false_positive`, `closed`

### 4.4 批量更新告警状态

```
PATCH /api/v1/alerts/batch-status
```

**请求**:
```json
{
  "alert_ids": [1, 2, 3],
  "status": "closed"
}
```

### 4.5 告警聚合

```
POST /api/v1/alerts/aggregate
```

### 4.6 告警趋势统计

```
GET /api/v1/alerts/trend?days=7
```

**响应**:
```json
{
  "code": 0,
  "data": {
    "by_day": [{"date": "2026-05-01", "count": 10}],
    "by_severity": [{"severity": "high", "count": 5}],
    "by_attack_type": [{"type": "SQL Injection", "count": 3}]
  }
}
```

---

## 5. AI 研判接口

### 5.1 单告警 AI 研判

```
POST /api/v1/ai/analyze/alert/{alert_id}
```

**权限**: analyst/admin

**请求**:
```json
{
  "use_rag": true,
  "include_context": true
}
```

**响应**:
```json
{
  "code": 0,
  "data": {
    "analysis_id": 501,
    "summary": "事件摘要",
    "risk_level": "high",
    "attack_stage": "漏洞尝试",
    "suggestion": "处置建议",
    "false_positive_possibility": "low",
    "management_summary": "管理层摘要",
    "technical_steps": ["步骤1", "步骤2"],
    "evidence": ["证据1"],
    "impact": "影响范围"
  }
}
```

**错误**: `40401` 告警不存在, `50001` AI 服务调用失败, `50002` AI 配置缺失

### 5.2 攻击链 AI 摘要

```
POST /api/v1/ai/analyze/chain/{chain_id}
```

### 5.3 查询 AI 研判历史

```
GET /api/v1/ai/analyses
```

**查询参数**: target_type (alert/event/chain), target_id, status (success/failed/fallback)

### 5.4 查询单条研判详情

```
GET /api/v1/ai/analyses/{analysis_id}
```

### 5.5 人工修订 AI 结果 (AI-08)

```
PUT /api/v1/ai/analyses/{analysis_id}/revise
```

**权限**: analyst/admin

**请求**:
```json
{
  "summary": "修订后的摘要",
  "risk_level": "high",
  "suggestion": "修订后的建议",
  "revision_comment": "根据补充日志修正研判结论"
}
```

**响应**: 返回完整的修订后研判对象，包含 `is_revised: true` 和修订人信息。

---

## 6. 攻击链接口

### 6.1 查询攻击链列表

```
GET /api/v1/attack-chains
```

### 6.2 生成攻击链

```
POST /api/v1/attack-chains/generate
```

**请求**:
```json
{
  "src_ip": "192.168.1.100",
  "asset": "10.0.0.5",
  "start_time": "2026-05-07 09:00:00",
  "end_time": "2026-05-07 12:00:00"
}
```

**响应**:
```json
{
  "code": 0,
  "data": {
    "chain_id": 301,
    "chain_no": "CHAIN-20260507-0001",
    "stage_count": 4,
    "confidence": "medium",
    "risk_score": 88
  }
}
```

### 6.3 查询攻击链详情

```
GET /api/v1/attack-chains/{chain_id}
```

返回攻击链节点列表，每节点包含：阶段、标题、时间、证据。

### 6.4 生成 AI 摘要

```
POST /api/v1/attack-chains/{chain_id}/ai-summary
```

### 6.5 手动修正攻击链 (T-08)

```
PUT /api/v1/attack-chains/{chain_id}
```

### 6.6 删除攻击链

```
DELETE /api/v1/attack-chains/{chain_id}
```

---

## 7. 报告接口

### 7.1 查询报告列表

```
GET /api/v1/reports
```

### 7.2 生成报告

```
POST /api/v1/reports/generate
```

**请求**:
```json
{
  "report_type": "chain",
  "target_id": 301,
  "template_id": 1,
  "use_ai_polish": true
}
```

### 7.3 查询报告详情

```
GET /api/v1/reports/{report_id}
```

返回 Markdown 和 HTML 格式报告内容。

### 7.4 删除报告

```
DELETE /api/v1/reports/{report_id}
```

---

## 8. 知识库接口

### 8.1 查询知识文档列表

```
GET /api/v1/knowledge
```

### 8.2 创建/更新/删除知识文档

```
POST   /api/v1/knowledge
PUT    /api/v1/knowledge/{doc_id}
DELETE /api/v1/knowledge/{doc_id}
```

### 8.3 知识检索 (RAG)

```
GET /api/v1/knowledge/search?q=SQL注入&limit=5
```

---

## 9. 仪表盘接口

### 9.1 仪表盘统计数据

```
GET /api/v1/dashboard/stats
```

返回告警总数、趋势、风险分布等。

---

## 10. 系统配置接口

### 10.1 查询系统配置

```
GET /api/v1/configs
```

**权限**: admin

### 10.2 更新系统配置

```
PUT /api/v1/configs/{config_key}
```

**请求**:
```json
{
  "config_value": "gpt-4.1-mini"
}
```

---

## 11. 系统管理接口

### 11.1 系统健康检查 (S-05)

```
GET /api/v1/system/health
```

**权限**: 登录用户

**响应**:
```json
{
  "code": 0,
  "data": {
    "status": "healthy",
    "checks": {
      "database": "ok",
      "rules": "ok (26 rules)",
      "openai": "configured",
      "uploads": "ok"
    },
    "timestamp": "2026-05-08T10:00:00+00:00"
  }
}
```

### 11.2 一键导入演示数据

```
POST /api/v1/system/demo/import
```

按顺序执行：生成演示日志 → 解析入库 → 规则检测 → 攻击链生成 → 资产发现。

### 11.3 审计日志查询

```
GET /api/v1/system/audit-logs?action=login&page=1&page_size=20
```

---

## 12. 用户管理接口

### 12.1 查询用户列表

```
GET /api/v1/users
```

### 12.2 创建用户

```
POST /api/v1/users
```

### 12.3 启用/禁用用户

```
POST /api/v1/users/{user_id}/toggle-status
```

---

## 13. 资产接口

### 13.1 查询资产列表

```
GET /api/v1/assets
```

### 13.2 资产详情

```
GET /api/v1/assets/{asset_id}
```

### 13.3 发现资产

```
POST /api/v1/assets/discover
```

---

## 14. 注释/笔记接口

### 14.1 查询告警注释

```
GET /api/v1/comments/{alert_id}
```

### 14.2 添加注释

```
POST /api/v1/comments/{alert_id}
```

---

## 15. 通知接口

### 15.1 发送通知

```
POST /api/v1/notifications/send
```

支持：企业微信、钉钉、飞书、通用 Webhook、邮件。

---

## 16. 调度器接口

### 16.1 查询定时任务状态

```
GET /api/v1/scheduler
```

### 16.2 启停定时任务

```
POST /api/v1/scheduler/{task_name}/toggle
```

---

## 数据表清单

| 表名 | 说明 | 关联模块 |
|------|------|----------|
| users | 用户表 | 认证、用户管理 |
| roles | 角色表 | 权限控制 |
| user_roles | 用户角色关联 | 权限控制 |
| audit_logs | 审计日志 | 系统管理 |
| raw_logs | 原始日志 | 日志模块 |
| log_import_tasks | 导入任务 | 日志模块 |
| detection_rules | 检测规则 | 规则引擎 |
| alerts | 告警表 | 告警模块 |
| alert_evidences | 告警证据 | 告警模块 |
| alert_events | 聚合事件 | 告警模块 |
| event_alert_relations | 事件-告警关联 | 告警模块 |
| alert_tags | 告警标签 | 告警模块 |
| attack_stages | 攻击阶段字典 | 攻击链 |
| attack_chains | 攻击链 | 攻击链 |
| attack_chain_nodes | 攻击链节点 | 攻击链 |
| ai_analyses | AI 研判结果 | AI 模块 |
| ai_call_logs | AI 调用记录 | AI 模块 |
| knowledge_docs | 知识文档 | RAG |
| knowledge_chunks | 知识片段 | RAG |
| reports | 报告表 | 报告模块 |
| report_templates | 报告模板 | 报告模块 |
| system_configs | 系统配置 | 系统管理 |
| assets | 资产表 | 资产模块 |
| asset_relations | 资产关联 | 资产模块 |
| alert_comments | 告警注释 | 注释模块 |
| alert_suppressions | 告警抑制 | 抑制模块 |
| login_logs | 登录日志 | 审计 |
| user_preferences | 用户偏好 | 用户模块 |
