import paramiko
import logging

# 配置日志
logging.basicConfig(filename='/var/log/xos.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def modify_ssh_config(ip, port, username, password):
    # 远程服务器信息
    ssh_config = {
        'hostname': ip,
        'port': port,
        'username': username,
        'password': password
    }

    # 要修改的配置项
    config_changes = {
        'PubkeyAuthentication': 'yes',
        'PasswordAuthentication': 'yes',
        'PermitRootLogin': 'yes',
        'Port': '22'
    }

    # 创建 SSH 客户端
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 连接远程服务器
        client.connect(**ssh_config)

        # 拷贝原始配置文件到 /root/ 目录下
        client.exec_command('sudo cp /etc/ssh/sshd_config /root/sshd_config_modified')

        # 修改配置文件
        for key, value in config_changes.items():
            client.exec_command(f"sudo sed -i 's/^#*{key} .*/{key} {value}/' /root/sshd_config_modified")

        # 将修改后的配置文件拷贝回原始位置
        client.exec_command('sudo cp /root/sshd_config_modified /etc/ssh/sshd_config')

        # 重启 SSH 服务
        client.exec_command('sudo systemctl restart sshd')
        logging.info("sshd 配置修改完成,已经重启服务!")

    except Exception as e:
        logging.error(f"ssh配置修改异常,请检查账号密码和端口: {e}")

    finally:
        # 关闭 SSH 连接
        client.close()

