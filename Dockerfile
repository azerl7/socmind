FROM python:3.12-slim

WORKDIR /app

# 安装 Python 依赖(用国内镜像源,build 更快)
COPY requirements.txt .
RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt

# 复制项目
COPY . .

# 创建数据目录
RUN mkdir -p /app/data uploads demo_data

EXPOSE 5000

# 默认启动命令(被 docker-compose 的 command 覆盖)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "wsgi:app"]