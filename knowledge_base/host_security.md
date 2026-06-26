# 主机安全运维知识库

## SSH 安全加固建议
- 禁用 root 用户直接 SSH 登录：在 /etc/ssh/sshd_config 中设置 PermitRootLogin no
- 使用密钥认证代替密码认证： PasswordAuthentication no
- 修改默认 SSH 端口（22 → 非标准端口）：Port 2222
- 配置 fail2ban 自动封禁暴力破解 IP
- 启用 SSH 双因素认证（Google Authenticator）
- 定期审计 /var/log/auth.log 和 /var/log/secure 中的异常登录记录

## Linux 主机入侵检测要点
- 关注 /etc/passwd 和 /etc/shadow 文件修改时间
- 使用 `last` 和 `lastb` 检查近期登录记录
- 检查正在运行的进程和网络连接：ps aux、netstat -antp
- 关注 SUID 文件变化：find / -perm -4000
- 检查 cron 任务和系统定时器
- 查看 .bash_history 中的可疑命令（curl、wget、python反弹shell）

## 暴力破解防御策略
- 配置合理的密码策略：12位以上、大小写+数字+特殊字符
- 启用账号锁定策略：pam_tally2 或 faillock
- 部署 WAF 和 IPS 拦截暴力破解流量
- 建议在 10 分钟内同 IP SSH 登录失败超过 5 次即触发告警
- 使用 CrowdSec 或 Fail2ban 实现自动封禁

## 权限提升检测
- 监控 sudo 命令执行日志，特别关注非 root 用户使用 sudo -u root
- 检测可疑的 sudo 命令：cat /etc/shadow、useradd、chmod 777
- 关注内核漏洞利用：脏牛、脏管、PwnKit
- 检查 Docker 容器逃逸风险
- 监控 SUID/GUID 文件和 ACL 权限变更

## 后门与持久化检测
- 检查 SSH authorized_keys 文件中是否有异常的密钥
- 检测系统服务：systemctl list-units --type=service
- 关注 LD_PRELOAD 和 .bashrc/.profile 修改
- 检查 WebShell 特征：系统命令执行、文件上传、权限提升
- 监控 /tmp 和 /var/tmp 目录的可执行文件创建
