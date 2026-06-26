# SOCMind 部署文档

## 快速启动（开发模式）

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量（可选，有默认值）
copy .env.example .env
# 编辑 .env 修改数据库连接等配置

# 3. 初始化数据库
python scripts/init_db.py

# 4. 生成演示数据
python scripts/generate_demo_logs.py

# 5. 启动服务
python app.py

# 6. 访问
# http://localhost:5000
# 默认账号: admin / admin123
```

## Docker 部署

```bash
# 一键启动
docker compose up -d

# 查看日志
docker compose logs -f flask

# 停止
docker compose down
```

## CLI 管理工具

```bash
python manage.py stats          # 平台统计
python manage.py health         # 健康检查
python manage.py purge          # 清理过期数据
python manage.py backup_db      # 备份数据库
python manage.py create_admin   # 创建管理员
python manage.py export_rules   # 导出检测规则
python manage.py reset_password <user> <pass>
```

## 测试

```bash
python -m pytest tests/ -v
```
