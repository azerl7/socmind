"""SOCMind WSGI 入口(生产环境用)

注意:不能用 app.py 名字,因为跟 app/ 目录同名,
Python import 规则会优先选包(package)而非模块(module),
导致 gunicorn 找不到 app 变量。
"""
import os

from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "production"))


if __name__ == "__main__":
    # 本地也能直接跑: python wsgi.py
    app.run(host="0.0.0.0", port=5000, debug=False)