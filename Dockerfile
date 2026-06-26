FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖（MySQL client + 可选 weasyprint 依赖）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目
COPY . .

# 创建数据目录
RUN mkdir -p uploads demo_data

EXPOSE 5000

# 默认启动命令（被 docker-compose 的 command 覆盖）
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
