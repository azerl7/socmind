# SOCMind 数据库设计文档

## 数据表总览

| 表名 | 说明 |
|------|------|
| users | 用户表 |
| roles | 角色表 |
| user_roles | 用户角色关联表 |
| raw_logs | 原始日志表 |
| log_import_tasks | 日志导入任务表 |
| detection_rules | 检测规则表 |
| alerts | 安全告警表 |
| alert_evidences | 告警证据表 |
| alert_events | 聚合安全事件表 |
| event_alert_relations | 事件与告警关联表 |
| alert_tags | 告警标签表 |
| alert_tag_relations | 告警-标签关联表 |
| attack_stages | 攻击阶段字典表 |
| attack_chains | 攻击链表 |
| attack_chain_nodes | 攻击链节点表 |
| ai_analyses | AI 研判结果表 |
| ai_call_logs | AI 调用记录表 |
| knowledge_docs | RAG 知识文档表 |
| reports | 报告表 |
| report_templates | 报告模板表 |
| system_configs | 系统配置表 |
| audit_logs | 操作审计日志表 |
| assets | 资产表 |
| asset_relations | 资产关联关系表 |
| alert_comments | 告警评论表 |
| alert_suppressions | 告警抑制规则表 |
| login_logs | 登录日志表 |
| user_preferences | 用户偏好表 |

## 核心表关系

- alerts → detection_rules (rule_id)
- alerts → raw_logs (raw_log_id)
- alert_evidences → alerts (alert_id)
- event_alert_relations → alert_events (event_id) + alerts (alert_id)
- attack_chains → alert_events (event_id)
- attack_chain_nodes → attack_chains (chain_id) + alerts (alert_id)
- ai_analyses → polymorphic (target_type + target_id)
- asset_relations → assets (src_asset_id + dst_asset_id)
