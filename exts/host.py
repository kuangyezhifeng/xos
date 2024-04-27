# -*- coding: utf-8 -*-
from flask import Flask, request, redirect, url_for, flash
from datetime import datetime
from subprocess import Popen, PIPE
from exts.proxy import *
from exts.ssh import modify_ssh_config
import subprocess
import time
import secrets
import uuid
import os
import random
import logging
import string
import paramiko

# Configure logging
logging.basicConfig(filename='/var/log/xos.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# 定义路径变量
LOCAL_PATH = "/usr/local/xos/static/config"
CHECK_PATH = '/usr/local/xos/xray/xray-check.json'
XRAY_EXTRACT_PATH = "/usr/local/"
XRAY_SYMLINK_PATH = "/usr/sbin/xray"
XRAY_CONFIG_PATH = "/usr/local/xray/config.json"
LOCAL_XRAY_FILE = "/usr/local/xos/static/xray.tar.gz"
XRAY_EXEC_FILE = "/usr/local/xray/xray"
TMP_XRAY_FILE = "/tmp/xray.tar.gz"
TMP = "/tmp"
XRAY_GITHUB_URI = "https://github.com/XTLS/Xray-core/releases/download/v1.8.10/Xray-linux-64.zip"
gltest_result = {}


def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def generate_random_account(length=6):
    return ''.join(random.choice(string.digits) for i in range(length))


def generate_vmess_link(protocol, ip, port):
    kcp_json = {
        "v": "2",
        "ps": "",
        "add": "ip",
        "port": "10808",
        "id": "6d7ec93d-b229-45cc-b241-86c0135e04f3",
        "aid": "0",
        "scy": "auto",
        "net": "kcp",
        "type": "wechat-video",
        "host": "",
        "path": "8YbN1oO964",
        "tls": "none",
        "sni": "",
        "alpn": "",
        "fp": ""
    }

    tcp_json = {
        "v": "2",
        "ps": "vmess_tcp",
        "add": "ip",
        "port": "10808",
        "id": "3f14577b-d35e-4832-f8ea-ec0d114692ec",
        "aid": "0",
        "scy": "auto",
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": "none",
        "sni": "",
        "alpn": "",
        "fp": ""
    }
    if protocol == 'vmess_tcp':
        tcp_json['add'] = ip
        tcp_json['port'] = int(port)
        tcp_json['id'] = str(uuid.uuid4())

        vmess_link = encode_vmess_link(tcp_json)
        return vmess_link

    elif protocol == 'vmess_kcp':
        kcp_json['add'] = ip
        kcp_json['port'] = int(port)
        kcp_json['id'] = str(uuid.uuid4())
        kcp_json['path'] = secrets.token_urlsafe(8)
        vmess_link = encode_vmess_link(kcp_json)
        return vmess_link


import uuid

def generate_vless_link(protocol, ip, port):
    vless_json = {
        "uuid": str(uuid.uuid4()),
        "ip": ip,
        "port": port,
        "encryption": "none",
        "flow": "xtls-rprx-vision",
        "security": "reality",
        "sni": "www.cloudflare.com",
        "fp": "chrome",
        "pbk": "S-g0oP36DShii1uPOnZDSEhp_wQghX6h68PgMivOmD4",
        "type": "tcp",
        "headerType": "none",
        "email": "kuangye6@gmail.com"
    }

    # 构建 URL 字符串
    vless_link = f"vless://{vless_json['uuid']}@{vless_json['ip']}:{vless_json['port']}?"
    vless_link += f"encryption={vless_json['encryption']}&"
    vless_link += f"flow={vless_json['flow']}&"
    vless_link += f"security={vless_json['security']}&"
    vless_link += f"sni={vless_json['sni']}&"
    vless_link += f"fp={vless_json['fp']}&"
    vless_link += f"pbk={vless_json['pbk']}&"
    vless_link += f"type={vless_json['type']}&"
    vless_link += f"headerType={vless_json['headerType']}#"
    vless_link += f"{vless_json['email']}"

    return vless_link


def parse_ip_addresses(address_list):
    all_addresses = []

    for address in address_list:
        try:
            # 尝试解析为 IP 地址
            ip = ipaddress.ip_address(address)
            all_addresses.append(str(ip))
        except ValueError:
            try:
                # 尝试解析为网络地址
                network = ipaddress.ip_network(address, strict=False)
                # 将网络地址转换为 IP 地址列表
                all_addresses.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                # 无法解析为有效的 IP 地址或网络地址
                pass

    return all_addresses


# 添加ssh免密登录
def setup_ssh_key_authentication(host_record):
    host_id = host_record.id
    ip = host_record.ip
    port = host_record.port
    user = host_record.account
    password = host_record.password

    modify_ssh_config(ip, port, user, password)
    #  解决系统识别特殊字符报错问题
    password = escape_password(password)
    if all([host_id, ip, port, user, password]):

        cmd = f"export SSHPASS={password} && sshpass -e ssh-copy-id -o StrictHostKeyChecking=no -p {port} {user}@{ip}"
        logging.info(f"命令:{cmd}")
        result = os.system(cmd)

        process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        host = Host.query.get(host_id)

        if result == 0 or process.returncode == 0:
            host.active = 'Active'
            logging.info("远程主机免密登录成功!")

        else:
            logging.error(f"免密命令执行失败：{stderr.decode('utf-8')}")
            host.active = 'Inactive'
        db.session.commit()


# 密码转义功能
def escape_password(password):
    k = password
    v = ''
    for i in k:
        if i == '\\':
            v += '\\\\'
        elif i == '*':
            v += '\*'
        elif i == '&':
            v += '\&'
        elif i == ']':
            v += '\]'
        elif i == '[':
            v += '\['
        elif i == '+':
            v += '\+'
        elif i == '-':
            v += '\-'
        elif i == '@':
            v += '\@'
        elif i == '#':
            v += '\#'
        elif i == '$':
            v += '\$'
        elif i == "'":
            v += "\\'"
        elif i == '?':
            v += '\?'
        elif i == '^':
            v += '\^'
        elif i == '.':
            v += '\.'
        elif i == '!':
            v += '\!'
        elif i == '(':
            v += '\('
        elif i == ')':
            v += '\)'
        elif i == ';':
            v += '\;'
        elif i == '<':
            v += '\<'
        elif i == '>':
            v += '\>'
        elif i == '`':
            v += '\`'
        else:
            v += i
    return v


def get_remote_ip_addresses(host, username, password, port):
    try:
        # 创建 SSH 客户端
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 连接到远程服务器
        ssh_client.connect(hostname=host, port=port, username=username, password=password)
        # 执行命令以获取 IP 地址
        stdin, stdout, stderr = ssh_client.exec_command('hostname -I')
        # 读取输出
        output = stdout.read().decode().strip()
        # 关闭 SSH 连接
        ssh_client.close()
        # 将输出的 IP 地址拆分
        remote_ips = output.split()

        # 将 IP 地址添加到数据库
        existing_ips = set()
        for ip in remote_ips:
            existing_record = Host_Config.query.filter_by(main_ip=host, auxiliary_ip=ip).first()
            if existing_record:
                existing_ips.add(ip)

        new_host_configs = [Host_Config(main_ip=host, auxiliary_ip=ip) for ip in remote_ips if ip not in existing_ips]
        db.session.add_all(new_host_configs)
        db.session.commit()

        logging.info(f"成功从远程服务器 {host} 中检索到 IP 地址")
    except Exception as e:
        logging.error(f"无法从远程服务器 {host} 中检索 IP 地址: {e}")


def remote_install_unzip(ssh_client):
    # 执行 hostnamectl 命令获取更准确的信息
    stdin, stdout, stderr = ssh_client.exec_command("hostnamectl")
    output = stdout.read().decode().lower()

    # 根据操作系统类型选择安装命令
    if 'ubuntu' in output or 'debian' in output:
        command = "sudo apt update && sudo apt-get install -y unzip"
        logging.info('远程ubuntu系统安装unzip......')

    elif 'centos' in output or 'red hat' in output:
        command = "sudo yum install -y unzip"
        logging.info('远程centos系统安装unzip......')

    else:
        # 未知的操作系统类型
        return False

    # 执行安装命令
    stdin, stdout, stderr = ssh_client.exec_command(command)
    # 等待命令执行完成
    exit_status = stdout.channel.recv_exit_status()

    # 如果命令执行成功（退出状态码为0），返回True，否则返回False
    if exit_status == 0:
        return True
    else:
        return False



def get_xray_status(ssh_client):
    # 检查 Xray 版本
    check_cmd = "xray -version"
    stdin, stdout, stderr = ssh_client.exec_command(check_cmd)

    # 读取命令执行结果
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    # 检查命令执行结果中是否包含 Xray 版本信息
    if "Xray" in output:
        logging.info("Xray 已安装在远程主机上。")
        return True
    else:
        logging.info("Xray 未安装在远程主机上。")
        return False


def get_country_code(ssh_client):
    command = "curl ipinfo.io"
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode()

    if re.search(r'\bCN\b', output):
        logging.info("中国服务器启用本地复制文件安装")
        return "CN"
    else:
        logging.info("国外服务器启用GITHUB下载安装程序")
        return "Foreign"


def sync_xray_config(ssh_client,xray_config):
    try:
        ftp = ssh_client.open_sftp()
        ftp.put(xray_config, XRAY_CONFIG_PATH)
        ftp.close()
        logging.info(f"已将文件从本地 {xray_config} 复制到远程服务器的 {XRAY_CONFIG_PATH}")
        return True

    except Exception as e:
        logging.error(f"将文件从本地 {xray_config} 复制到远程服务器的 {XRAY_CONFIG_PATH} 时出现错误: {e}")
        return False


def restart_remote_xray(ssh_client):
    try:
        restart_command = "systemctl restart xray.service"
        stdin, stdout, stderr = ssh_client.exec_command(restart_command)
        if stdout.channel.recv_exit_status() == 0:
            logging.info("Xray服务重启成功。")
            return True
        else:
            logging.error("Xray服务重启失败。")
            return False

    except Exception as e:
        logging.error(f"Xray服务重启时出现错误: {e}")
        return False

def restart_remote_xray_service(ssh_client):
    try:
        restart_command = "systemctl restart xray.service"
        stdin, stdout, stderr = ssh_client.exec_command(restart_command)
        if stdout.channel.recv_exit_status() == 0:
            logging.info("Xray服务重启成功。")
            return True
        else:
            logging.error("Xray服务重启失败。")
            return False

    except Exception as e:
        logging.error(f"Xray服务重启时出现错误: {e}")
        return False


def china_install_xray(ssh_client):
    # 连接 SFTP 客户端
    sftp = ssh_client.open_sftp()
    try:
        # 将本地文件复制到远程服务器
        sftp.put(LOCAL_XRAY_FILE, TMP_XRAY_FILE)
        # 执行解压、权限设置等操作
        mkdir_cmd = "mkdir -p /usr/local/xray"
        extract_cmd = f"tar -xzf {TMP_XRAY_FILE} -C {XRAY_EXTRACT_PATH}"
        remove_cmd = f"rm {TMP_XRAY_FILE}"
        chmod_cmd = "chmod +x /usr/local/xray/xray"
        # 设置权限的命令
        setcap_cmd = "sudo setcap 'cap_net_bind_service=+ep' /usr/local/xray/xray"

        # 合并并命令串
        command = f"{mkdir_cmd} && {extract_cmd} && {remove_cmd} && {setcap_cmd} && {chmod_cmd}"
        stdin, stdout, stderr = ssh_client.exec_command(command)

        if stdout.channel.recv_exit_status() != 0:
            logging.error(f"远程服务器安装 Xray 失败")
        else:
            logging.info(f"远程服务器安装Xray成功")

        # 创建符号链接
        symlink_cmd = f"ln -s {XRAY_EXEC_FILE} {XRAY_SYMLINK_PATH}"
        ssh_client.exec_command(symlink_cmd)

    finally:
        # 关闭 SFTP 客户端连接
        sftp.close()

def foreign_install_xray(ssh_client):
    if remote_install_unzip(ssh_client):
        mkdir_cmd = "mkdir -p /usr/local/xray"
        download_cmd = f"curl -LO {XRAY_GITHUB_URI}"
        extract_cmd = f"unzip -o Xray-linux-64.zip -d /usr/local/xray"
        remove_cmd = "rm Xray-linux-64.zip"
        chmod_cmd = "chmod +x /usr/local/xray/xray"
        # 设置权限的命令
        setcap_cmd = "sudo setcap 'cap_net_bind_service=+ep' /usr/local/xray/xray"
        # 执行命令与合并命令串
        command = f"{mkdir_cmd};{download_cmd} && {extract_cmd} && {remove_cmd} && {setcap_cmd} && {chmod_cmd}"
        stdin, stdout, stderr = ssh_client.exec_command(command)

        if stdout.channel.recv_exit_status() != 0:
            error_message = stderr.read().decode()
            logging.error(f"远程服务器安装 Xray 失败: {error_message}")
            raise Exception(f"Failed to install Xray: {error_message}")
        else:
            logging.info(f"远程服务器安装Xray成功")

        # 创建符号链接
        symlink_cmd = f"ln -s {XRAY_EXEC_FILE} {XRAY_SYMLINK_PATH}"
        ssh_client.exec_command(symlink_cmd)
    else:
        logging.error("unzip 安装错误")


def remote_xray_service_write(ssh_client):
    # 创建 Xray systemd 服务
    service_content = f"""
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart={XRAY_EXEC_FILE} -config {XRAY_CONFIG_PATH}
Restart=on-failure
User=nobody
RestartSec=3
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"""
    with open("xray.service", "w") as service_file:
        service_file.write(service_content)

    # 上传 Xray 服务文件
    ftp = ssh_client.open_sftp()
    ftp.put("xray.service", "/etc/systemd/system/xray.service")
    ftp.close()

    # 重载 systemd 并启动 Xray 服务
    reload_start_cmd = "systemctl daemon-reload && systemctl start xray.service && systemctl enable xray.service"
    stdin, stdout, stderr = ssh_client.exec_command(reload_start_cmd)
    if stdout.channel.recv_exit_status() != 0:
        logging.error("远程xray设置系统服务错误")

    logging.info("远程xray设置系统服务成功")



# 生成单个vmess配置和vmess URI
def generate_vmess_json(data):
    ip = data.get("add")
    port = data.get("port")
    tag = str(random.randint(10000000, 99999999))
    client_id = data.get("id", str(uuid.uuid4()))

    if 'tcp' == data.get('net'):
        inbound = {
            "listen": ip,
            "port": port,
            "protocol": "vmess",
            "settings": {"clients": [{"id": client_id, "alterId": 0}]},
            "streamSettings": {"network": "tcp"},
            "tag": f"inbound-{tag}",
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }

    elif 'kcp' == data.get('net'):
        inbound = {
            "listen": ip,
            "port": port,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": client_id,
                        "alterId": 0
                    }
                ],
                "disableInsecureEncryption": False
            },
            "streamSettings": {
                "network": "kcp",
                "security": "none",
                "kcpSettings": {
                    "mtu": 1350,
                    "tti": 20,
                    "uplinkCapacity": 5,
                    "downlinkCapacity": 20,
                    "congestion": False,
                    "readBufferSize": 2,
                    "writeBufferSize": 2,
                    "header": {
                        "type": "wechat-video"
                    },
                    "seed": data.get("path")
                }
            },
            "tag": f"inbound-{tag}",
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }

    outbound = {
        "sendThrough": ip,
        "protocol": "freedom",
        "settings": {"domainStrategy": "UseIP"},
        "tag": f"outbound-{tag}",
    }

    routing = {
        "type": "field",
        "inboundTag": f"inbound-{tag}",
        "outboundTag": f"outbound-{tag}",
    }

    return inbound, outbound, routing


def generate_vless_json(data):
    ip = data.get("ip")
    port = data.get("port")
    tag = str(random.randint(10000000, 99999999))
    client_id = data.get("uuid", str(uuid.uuid4()))

    inbound = {
        "listen": ip,
        "port": port,
        "protocol": "vless",
        "settings":
            {
                "clients":
                    [
                        {
                            "id": client_id,
                            "email": "kuangye6@xray.com",
                            "flow": "xtls-rprx-vision"
                        }
                    ],
                "decryption": "none",
                "fallbacks":
                    []
            },
        "streamSettings":
            {
                "network": "tcp",
                "security": "reality",
                "realitySettings":
                    {
                        "show": False,
                        "dest": "www.cloudflare.com:443",
                        "xver": 0,
                        "serverNames":
                            [
                                "www.cloudflare.com"
                            ],
                        "privateKey": "MGpadXgOh0X_ylHa8y4OO_0QdRIVEXgwCdeJ3wkFUEo",
                        "publicKey": "S-g0oP36DShii1uPOnZDSEhp_wQghX6h68PgMivOmD4",
                        "minClient": "",
                        "maxClient": "",
                        "maxTimediff": 0,
                        "shortIds":
                            [
                                "",
                                "53",
                                "4d8c",
                                "e17859",
                                "85a23941"
                            ]
                    },
                "tcpSettings":
                    {
                        "header":
                            {
                                "type": "none"
                            },
                        "acceptProxyProtocol": False
                    }
            },
        "tag": f"inbound-{tag}",
        "sniffing":
            {
                "enabled": True,
                "destOverride":
                    [
                        "http",
                        "tls",
                        "quic"
                    ]
            }
    }
    outbound = {
        "sendThrough": ip,
        "protocol": "freedom",
        "settings": {"domainStrategy": "UseIP"},
        "tag": f"outbound-{tag}",
    }

    routing = {
        "type": "field",
        "inboundTag": f"inbound-{tag}",
        "outboundTag": f"outbound-{tag}",
    }

    return inbound, outbound, routing


# 生成socks配置
def generate_socks_json(data):
    ip = data.get("target_ip")
    port = data.get("target_port", 10808)
    tag = str(random.randint(10000000, 99999999))

    username = data.get("username")
    password = data.get("password")

    inbound = {
        "tag": f"inbound-{tag}",
        "port": port,
        "listen": ip,
        "protocol": "socks",
        "settings": {
            "auth": "password",
            "udp": True,
            "accounts": [{"user": username, "pass": password}],
        },
    }

    outbound = {
        "sendThrough": ip,
        "protocol": "freedom",
        "settings": {"domainStrategy": "UseIP"},
        "tag": f"outbound-{tag}",
    }

    routing = {
        "type": "field",
        "inboundTag": f"inbound-{tag}",
        "outboundTag": f"outbound-{tag}",
    }

    return inbound, outbound, routing


def generate_and_save_configs(host_ip):
    xray_config = {"inbounds": [], "outbounds": [], "routing": {"rules": []}}

    # 查询特定主机ID下所有 proxy_url 不为空的记录
    hosts_with_proxy = Host_Config.query.filter(
        Host_Config.proxy_url.isnot(None),
        Host_Config.proxy_url != "",
        Host_Config.main_ip == host_ip
    ).all()
    # 解码 URL 并根据 protocol 分类
    for host in hosts_with_proxy:
        inbound, outbound, routing = None, None, None
        if host.protocol.lower() == 'vmess':
            decoded_data = decode_vmess_link(host.proxy_url)
            if decoded_data:
                inbound, outbound, routing = generate_vmess_json(decoded_data)
        elif host.protocol.lower() == 'vless':
            decoded_data = decode_vless_link(host.proxy_url)
            if decoded_data:
                inbound, outbound, routing = generate_vless_json(decoded_data)

        elif host.protocol.lower() == 'socks':
            decoded_data = decode_socks_link(host.proxy_url)
            if decoded_data:
                inbound, outbound, routing = generate_socks_json(decoded_data)

        if inbound and outbound and routing:
            # 添加到 xray_config 中
            xray_config["inbounds"].append(inbound)
            xray_config["outbounds"].append(outbound)
            xray_config["routing"]["rules"].append(routing)

    # 构建文件名，格式为 IP_月日时_config.json
    current_time = datetime.now().strftime("%m%d%H")
    # 使用 os.path.join() 来组合路径和文件名
    xray_config_file = os.path.join(TMP, f"{host_ip}_{current_time}_config.json")

    # 保存 xray_config 到文件
    save_xray_config(xray_config, xray_config_file)

    return xray_config_file


def xray_remote_service_handler(remote_host):
    # 连接远程服务器
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=remote_host)

        # 检查Xray安装状态
        if get_xray_status(ssh_client):
            pass
        else:
            # 根据国家安装Xray
            result = get_country_code(ssh_client)
            if result == "CN":
                china_install_xray(ssh_client)
            else:
                foreign_install_xray(ssh_client)

            # 写入远程Xray服务配置文件
            remote_xray_service_write(ssh_client)

        # 生成和保存配置文件
        xray_config_file = generate_and_save_configs(remote_host)
        sync_xray_config(ssh_client, xray_config_file)

        # 重启远程Xray服务
        restart_remote_xray(ssh_client)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        ssh_client.close()


def batch_proxies_set(protocol, addresses, port='10808', account=None, password=None):
    all_addresses = parse_ip_addresses(addresses)

    # 获取 Host_Config 表中所有 auxiliary_ip 字段的值
    existing_ips = [str(host.auxiliary_ip) for host in Host_Config.query.all() if host.auxiliary_ip]

    # 提交上来的ip地址只保留在Host_Config 表中的存在的 IP 地址
    filtered_ips = [ip for ip in all_addresses if ip in existing_ips]

    if protocol == 'socks' and filtered_ips:
        # 如果用户输入了账号密码，则使用用户输入的账号密码，否则生成随机的不同账号密码
        if account and password:
            for ip in filtered_ips:
                proxies = Host_Config.query.filter_by(auxiliary_ip=ip).first()
                # 代理信息写入数据库
                proxies.protocol = protocol
                proxies.proxy_url = f"socks://{ip}:{port}:{account}:{password}"
                logging.info(f"成功创建新的代理:{proxies.proxy_url}")
            db.session.commit()
        else:
            # 生成随机的不同账号密码
            for ip in filtered_ips:
                account = generate_random_account()
                password = generate_random_password()
                proxies = Host_Config.query.filter_by(auxiliary_ip=ip).first()
                # 代理信息写入数据库
                proxies.protocol = protocol
                proxies.proxy_url = f"socks://{ip}:{port}:{account}:{password}"
                logging.info(f"成功创建新的代理:{proxies.proxy_url}")
            db.session.commit()

    elif protocol in ['vmess_tcp', 'vmess_kcp'] and filtered_ips:
        for ip in filtered_ips:
            proxies = Host_Config.query.filter_by(auxiliary_ip=ip).first()
            if proxies:
                vmess_link = generate_vmess_link(protocol, ip, port)
                proxies.protocol = 'vmess'
                proxies.proxy_url = vmess_link
                logging.info(f"成功创建新的代理:{proxies.proxy_url}")
        db.session.commit()

    elif protocol in ['vless_reality'] and filtered_ips:
        for ip in filtered_ips:
            proxies = Host_Config.query.filter_by(auxiliary_ip=ip).first()
            if proxies:
                vless_link = generate_vless_link(protocol, ip, port)
                proxies.protocol = 'vless'
                proxies.proxy_url = vless_link
                logging.info(f"成功创建新的代理:{proxies.proxy_url}")
        db.session.commit()


def batch_get_proxies_info(addresses):
    all_addresses = parse_ip_addresses(addresses)

    # 获取 Host_Config 表中所有 auxiliary_ip 字段的值
    existing_ips = [str(host.auxiliary_ip) for host in Host_Config.query.all() if host.auxiliary_ip]

    # 保留存在于 Host_Config 表中的 IP 地址
    filtered_ips = [ip for ip in all_addresses if ip in existing_ips]

    # 创建查询，选择在 Host_Config 中 auxiliary_ip 匹配 filtered_ips 中任一 IP 的 proxy_url
    result = db.session.query(Host_Config.auxiliary_ip, Host_Config.proxy_url).filter(
        Host_Config.auxiliary_ip.in_(filtered_ips)
    ).all()
    # 返回IP和URL组合
    result_dict = {row[0]: row[1] for row in result if row[1] is not None}

    return result_dict


def create_tc_rules(remote_host, interface, proxies, max_retries=8):
    speed_limit_level = {}
    for tc in proxies:
        ip = tc.auxiliary_ip
        port = decode_socks_link(tc.proxy_url).get('target_port')
        speed_limit = tc.speed_limit
        # 生成唯一的class_id
        class_id = f"1:{int(speed_limit.rstrip('Mbit'))}"

        # 如果该速度值已经存在对应的class_id，则不添加新规则
        if speed_limit not in speed_limit_level:
            speed_limit_level[speed_limit] = class_id
        else:
            # 获取已存在的class_id
            class_id = speed_limit_level[speed_limit]
        retries = 0
        while retries < max_retries:
            # 添加限速规则
            tc_rule = (f"ssh {remote_host} tc class add dev {interface} parent 1: classid {class_id} htb rate "
                       f"{speed_limit}")
            if 'closed' not in subprocess.getstatusoutput(tc_rule)[1]:
                logging.info(f"添加限速规则成功: {ip}:{port} {speed_limit}")
                break
            else:
                retries += 1
                time.sleep(1)
        retries = 0
        while retries < max_retries:
            re_rule = (f"ssh {remote_host} tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip "
                       f"src {ip} match ip sport {port} 0xffff flowid {class_id}")

            if 'closed' not in subprocess.getstatusoutput(re_rule)[1]:
                logging.info(f"添加限速规则匹配IP和端口成功: {ip}:{port} {speed_limit}")
                break
            else:
                retries += 1
                time.sleep(1)


def create_tc_limit(remote_host, proxies, max_retries=8):
    retries = 0
    get_interface_command = f"ssh {remote_host} ip route show | grep default | awk '{{print $5}}'"
    # 执行获取网卡名称的命令
    while retries < max_retries:
        interface = subprocess.getstatusoutput(get_interface_command)
        if 'closed' not in interface[1]:
            interface = interface[1]
            logging.info(f"获取网络接口成功: {interface}")
            break
        else:
            retries += 1
            time.sleep(1)

    # 构建设置限速的命令
    retries = 0
    tc_command = f"ssh {remote_host} tc qdisc add dev {interface} root handle 1: htb default 12"
    while retries < max_retries:
        if 'closed' not in subprocess.getstatusoutput(tc_command)[1]:
            logging.info("已经创建限速根类!")
            break
        else:
            retries += 1
            time.sleep(1)

    # 清理限速规则
    retries = 0
    tc_rules_clear = f"ssh {remote_host}  tc filter del dev {interface} parent 1: "
    while retries < max_retries:
        if 'closed' not in subprocess.getstatusoutput(tc_rules_clear)[1]:
            logging.info("已经清理旧的限速规则!")
            break
        else:
            retries += 1
            time.sleep(1)

    create_tc_rules(remote_host, interface, proxies)


def batch_proxies_test(proxies):
    xray_config = {"inbounds": [], "outbounds": [], "routing": {"rules": []}}
    result = {}
    global test_result
    test_result.clear()


    # 存储已经生成的端口号
    used_ports = set()
    for proxy in proxies:
        proxies_id = proxy.id
        protocol = proxy.protocol
        proxy_url = proxy.proxy_url
        tag = generate_tag()

        # 生成端口号并检查是否重复
        while True:
            port = random.randint(1500, 65534)
            if port not in used_ports and not is_local_port_in_use(port):
                used_ports.add(port)
                break
        # 将端口号与代理ID关联起来
        result[proxies_id] = port

        if protocol == 'hysteria2':
            continue

        inbound, outbound, routing = generate_test_config(protocol, proxy_url, tag, port)

        if inbound and outbound and routing:
            xray_config["inbounds"].append(inbound)
            xray_config["outbounds"].append(outbound)
            xray_config["routing"]["rules"].append(routing)
        else:
            logging.error("无法生成配置.")
    # 保存配置
    save_xray_config(xray_config, CHECK_PATH)
    restart_xray_service('xray-check')

    # 调用多进程检测程序
    test_result = multi_process_test(result)

    for proxies_id, result in test_result.items():
        proxies = Host_Config.query.get(proxies_id)
        if result == 'Inactive':
            proxies.status = 'Inactive'
        else:
            proxies.status = 'Active'

    db.session.commit()

    # 执行关闭 xray-check 服务的命令
    os.system('sudo systemctl stop xray-check')

#
