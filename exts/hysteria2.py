import logging
import subprocess
import string
import secrets
import os

# 配置日志
logging.basicConfig(filename='/var/log/xos.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
LOCAL_HYSTERIA2 = "/usr/local/xos/xray/hysteria2"
REMOTE_HYSTERIA2 = "/usr/bin"
CONFIG_DIR = "/etc/hysteria2"


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password


def deploy_hysteria2(remote_host, remote_user, password, port=443, max_attempts=5):
    # 在远程服务器上创建配置文件夹
    for attempt in range(max_attempts):
        create_config_dir_command = f"ssh {remote_user}@{remote_host} 'sudo mkdir -p {CONFIG_DIR}'"
        create_config_dir_result = subprocess.run(create_config_dir_command, shell=True)

        if create_config_dir_result.returncode == 0:
            logging.info('创建hysteria2配置文件夹成功')
            break
        else:
            logging.error(f'第 {attempt + 1} 次尝试：创建hysteria2配置文件夹失败')

    # 复制本地程序到远程服务器
    for attempt in range(max_attempts):
        copy_command = f"scp {LOCAL_HYSTERIA2} {remote_user}@{remote_host}:{REMOTE_HYSTERIA2}"
        copy_result = subprocess.run(copy_command, shell=True)

        if copy_result.returncode == 0:
            logging.info(f'拷贝hysteria2到远程服务器{remote_host}成功')
            break
        else:
            logging.error(f'第 {attempt + 1} 次尝试：拷贝hysteria2到远程服务器{remote_host}失败')

    # 给远程hysteria2设置可执行权限
    for attempt in range(max_attempts):
        subprocess.run(f"ssh {remote_user}@{remote_host} 'sudo chmod +x {REMOTE_HYSTERIA2}/hysteria2'", shell=True)
        if copy_result.returncode == 0:
            logging.info('设置hysteria2可执行权限成功')
            break
        else:
            logging.error(f'第 {attempt + 1} 次尝试：设置hysteria2可执行权限失败')

    # 生成SSL证书
    for attempt in range(max_attempts):
        cert_key_path = "/etc/hysteria2/server.key"
        cert_crt_path = "/etc/hysteria2/server.crt"
        cert_subject = "/CN=bing.com"

        cert_command = (f"openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout {cert_key_path} "
                        f"-out {cert_crt_path} -subj '{cert_subject}' -days 36500")

        cert_result = subprocess.run(f"ssh {remote_user}@{remote_host} '{cert_command}'", shell=True)
        # 系统优化
        cmd1 = ["sysctl", "-w", "net.core.rmem_max=16777216"]
        cmd2 = ["sysctl", "-w", "net.core.wmem_max=16777216"]

        # 执行第一个命令
        subprocess.run(cmd1, shell=True)
        subprocess.run(cmd2, shell=True)

        if cert_result.returncode == 0:
            logging.info('生成自签证书成功')
            break
        else:
            logging.error(f'第 {attempt + 1} 次尝试：生成自签证书失败')

    # 创建systemd服务文件
    service_file_path = "/etc/systemd/system/hysteria2.service"
    service_content = f"""
[Unit]
Description=Hysteria 服务器服务
After=network.target

[Service]
Type=simple
ExecStart={REMOTE_HYSTERIA2}/hysteria2 server --config /etc/hysteria2/config.yaml
WorkingDirectory={REMOTE_HYSTERIA2}
User=root
Group=root
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

    # 写入服务文件
    for attempt in range(max_attempts):
        service_write_result = subprocess.run(
            f"echo '{service_content}' | ssh {remote_user}@{remote_host} 'sudo tee {service_file_path} > /dev/null'",
            shell=True)

        if service_write_result.returncode == 0:
            logging.info('写入hysteria2系统服务成功')
            break
        else:
            logging.error(f'第 {attempt + 1} 次尝试：写入hysteria2系统服务失败')

    # 创建hysteria配置文件
    config_file_path = f"{CONFIG_DIR}/config.yaml"
    config_content = f"""
listen: :{port}

tls:
  cert: {cert_crt_path}
  key: {cert_key_path}

auth:
  type: password
  password: {password}

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    
bandwidth:
  up: 1 gbps
  down: 1 gbps
"""

    # 写入配置文件
    for attempt in range(max_attempts):
        config_write_command = f"echo '{config_content}' | ssh {remote_user}@{remote_host} 'sudo tee {config_file_path}'"
        config_write_result = subprocess.run(config_write_command, shell=True)

        if config_write_result.returncode == 0:
            logging.info('写入hysteria2配置文件成功')
            break
        else:
            logging.error(f'第 {attempt + 1} 次尝试：写入hysteria2配置文件失败')

    # 重新加载systemd并启动服务
    for attempt in range(max_attempts):
        daemon_reload = subprocess.run(["ssh", f"{remote_user}@{remote_host}", "sudo", "systemctl", "daemon-reload"],
                       check=True)
        if daemon_reload.returncode == 0:
            logging.info('系统服务重载成功！')
        enable_service = subprocess.run(["ssh", f"{remote_user}@{remote_host}", "sudo", "systemctl", "enable", "hysteria2"],
                       check=True)
        if enable_service.returncode == 0:
            logging.info('系统服务开机启动成功！')

        start_service = subprocess.run(["ssh", f"{remote_user}@{remote_host}", "sudo", "systemctl", "start", "hysteria2"],
                       check=True)
        if start_service.returncode == 0:
            logging.info('成功启动hysteria2，可以连接和使用')

        subprocess.run(["ssh", f"{remote_user}@{remote_host}", "sudo", "systemctl", "restart", "hysteria2"],
                       check=True)

        if daemon_reload.returncode == 0 and start_service.returncode == 0:
            break
        else:
            continue


