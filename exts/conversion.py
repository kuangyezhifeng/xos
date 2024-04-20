import random
import string
import json
import uuid
import base64
import requests
import time
import re
import logging
import os
import tarfile
import subprocess
from app.models import *
from exts.proxy import generate_tag, is_local_port_in_use,generate_test_config,save_xray_config,restart_xray_service,multi_process_test
from exts.proxy import decode_proxy_link,generate_node_outbound

CHECK_PATH = '/usr/local/xos/xray/xray-check.json'
XRAY_CHECK = '/etc/systemd/system/xray-check.service'
# 文件保存已经生成的端口号的路径
PORTS_FILE_PATH = "/usr/local/xos/static/conversion_ports.txt"
test_result = {}
# Configure logging
logging.basicConfig(filename='/var/log/xos.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_random_string(length):
    """Generate a random string of given length."""
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


# def generate_random_port():
#     # 生成端口号并检查是否重复
#     while True:
#         random_port = random.randint(1024, 65534)
#         if not is_local_port_in_use(random_port):
#             break
#     return random_port
def generate_random_port():
    # 用于存储已经生成的端口号的集合
    used_ports = set()
    # 检查文件是否存在
    if os.path.exists(PORTS_FILE_PATH):
        with open(PORTS_FILE_PATH, "r") as file:
            used_ports = set(int(port) for port in file.read().splitlines())
    while True:
        random_port = random.randint(1024, 65534)
        if random_port not in used_ports and not is_local_port_in_use(random_port):
            used_ports.add(random_port)
            # 保存已使用的端口到文件
            with open(PORTS_FILE_PATH, "w") as file:
                file.write("\n".join(str(port) for port in used_ports))
            return random_port

def generate_random_id():
    """Generate a random UUID."""
    return str(uuid.uuid4())


def get_public_ip():
    try:
        # 使用一个提供公网 IP 的服务，比如 https://api.ipify.org
        response = requests.get('https://api.ipify.org')
        if response.status_code == 200:
            return response.text
        else:
            logging.info("获取公网地址:", response.status_code)
    except Exception as e:
       pass
    return None

public_ip = get_public_ip()

def generate_conversion_inbound(inbound_connection,tag):
    decode_data, protocol = decode_proxy_link(inbound_connection)
    if protocol == "socks":
        inbound_connection = {
            "port": int(decode_data.get('target_port', 0)),
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [
                    {
                        "user": decode_data.get('username', ''),
                        "pass": decode_data.get('password', ''),
                    }
                ],
                "udp": True
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "none"
                    }
                }
            },
            "tag": tag,
            "sniffing": {}
        }
        return inbound_connection

    elif protocol == "shadowsocks":
        # 获取 method、port 和 password 字段的值
        method = decode_data.get('method', 'aes-256-gcm')
        port = decode_data.get('port', '0')
        password = decode_data.get('password', 'password')
        inbound_connection = {
            "port": port,
            "protocol": "shadowsocks",
            "settings": {
                "method": method,
                "password": password,
                "network": "tcp,udp"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "none"
                    }
                }
            },
            "tag": tag,
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
        return inbound_connection

    elif protocol == "vmess":
        inbound_connection = {
            "port": decode_data.get('port', 0),
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": decode_data.get('id', ''),
                        "alterId": 64
                    }
                ],
                "disableInsecureEncryption": False
            },
            "streamSettings": {
            },
            "tag": tag,
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }

        if decode_data.get('net', '') == "kcp":
            inbound_connection["streamSettings"]["network"] = "kcp"
            inbound_connection["streamSettings"]["security"] = "none"
            inbound_connection["streamSettings"]["kcpSettings"] = {
                "mtu": 1350,
                "tti": 20,
                "uplinkCapacity": 5,
                "downlinkCapacity": 20,
                "congestion": False,
                "readBufferSize": 2,
                "writeBufferSize": 5,
                "header": {
                    "type": decode_data .get('type', ''),
                },
                "seed": decode_data.get('path', ''),
            }
        else:
            inbound_connection["streamSettings"]["network"] = "tcp"
            inbound_connection["streamSettings"]["security"] = "none"
            inbound_connection["streamSettings"]["tcpSettings"] = {
                "header": {
                    "type": "none"
                }
            }

        return inbound_connection

    if protocol == 'vless':
        inbound_connection = {
            "port": decode_data.get('port', ''),
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": decode_data.get('uuid', ''),
                        "email": "kuangye6@gmail.com",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none",
                "fallbacks": []
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": decode_data.get('sni', '')+":443",
                    "xver": 0,
                    "serverNames": [
                        decode_data.get('sni', '')
                    ],
                    "privateKey": "oKVwj79wHXjWIFUq0qkmdHXusmr4fQYPNeNM--6f03g",
                    "publicKey": "rYH4wPTVzSwtpXgI3U7YxppIP6oudD-425vT7pyhj1w",
                    "minClient": "",
                    "maxClient": "",
                    "maxTimediff": 0,
                    "shortIds": [
                        "",
                        "e6",
                        "04c2",
                        "a050ba",
                        "38492865"
                    ]
                },
                "tcpSettings": {
                    "header": {
                        "type": "none"
                    },
                    "acceptProxyProtocol": False
                }
            },
            "tag": tag,
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
        return inbound_connection

def conver_to_db(inbound_protocol, outbound_protocol, inbound_connection, proxy):
    if public_ip:
        # 如果成功获取到公网 IP，则写入数据库
        try:
            tag = generate_tag()
            new_conver = Conver(proxy_ip=public_ip, inbound_protocol=inbound_protocol, outbound_protocol=outbound_protocol, inbound_connections=inbound_connection,outbound_connections=proxy, tag=tag)
            db.session.add(new_conver)
            db.session.commit()
        except Exception as e:
            logging.error("Error occurred while writing to database:", e)

def generate_conversions(inbound_protocol, outbound_protocol, proxys):
    """
    Generate configurations based on the outbound_protocol type and
    convert them into protocol strings for inbound connections.
    """
    for proxy in proxys:
        if inbound_protocol == "socks" and proxy:
            port = generate_random_port()
            user = generate_random_string(10)
            password = generate_random_string(10)

            inbound_connection = f"{inbound_protocol}://{public_ip}:{port}:{user}:{password}"
            conver_to_db(inbound_protocol, outbound_protocol, inbound_connection, proxy)


        elif inbound_protocol == "shadowsocks" and proxy:
            port = generate_random_port()
            password = generate_random_string(10)
            algorithm = "aes-256-gcm"
            combined_data = f"{algorithm}:{password}"
            encoded_data = base64.b64encode(combined_data.encode()).decode()

            inbound_connection = f"ss://{encoded_data}@{public_ip}:{port}#shadowsocks"
            conver_to_db(inbound_protocol,outbound_protocol, inbound_connection, proxy)

        elif inbound_protocol == "vmess" and proxy:
            port = generate_random_port()
            vmess_uuid = generate_random_id()

            """Generate Vmess-KCP connection string."""
            config = {
                "v": "2",
                "ps": "",
                "add": public_ip,
                "port": port,
                "id": vmess_uuid,
                "aid": 64,
                "net": "kcp",
                "type": "wechat-video",
                "host": "",
                "path": "VA1vFM7DZn",
                "tls": ""
            }
            config_json = json.dumps(config)
            encoded_config = base64.b64encode(config_json.encode()).decode()
            inbound_connection = f"vmess://{encoded_config}"
            conver_to_db(inbound_protocol, outbound_protocol, inbound_connection, proxy)

        elif inbound_protocol == "vless" and proxy:
            port = generate_random_port()
            id = generate_random_id()
            host = public_ip
            encryption = "none"
            flow = "xtls-rprx-vision"
            security = "reality"
            sni = f"www.cloudflare.com"
            fp = "chrome"
            pbk = "rYH4wPTVzSwtpXgI3U7YxppIP6oudD-425vT7pyhj1w"
            type = "tcp"
            headerType = "none"

            inbound_connection = f"vless://{id}@{host}:{port}?encryption={encryption}&flow={flow}&security={security}&sni={sni}&fp={fp}&pbk={pbk}&type={type}&headerType={headerType}#{sni}"
            conver_to_db(inbound_protocol, outbound_protocol, inbound_connection, proxy)


def conversion_config(proxy):
    # 检查代理信息中的 flag 字段
    if proxy.flag == 1:
        proxy.flag = 0
    else:
        proxy.flag = 1

    # 提交更改
    db.session.commit()


def conversion_check_proxy(selected_items):
    xray_config = {"inbounds": [], "outbounds": [],"routing": {"rules": []}}
    result = {}
    global test_result
    test_result.clear()

    for proxy_id in selected_items:
        # 生成端口号并检查是否重复
        while True:
            port = random.randint(1024, 65534)
            if not is_local_port_in_use(port):
                break
        proxy = Conver.query.filter_by(id=proxy_id).first()
        protocol = proxy.outbound_protocol
        outbound_connections = proxy.outbound_connections.strip()
        tag = proxy.tag

        # 添加代理条件ID和测试端口对应关系
        result[proxy_id] = port
        inbound, outbound, routing = generate_test_config(protocol, outbound_connections, tag, port)

        if inbound and outbound and routing:
            xray_config["inbounds"].append(inbound)
            xray_config["outbounds"].append(outbound)
            xray_config["routing"]["rules"].append(routing)

        else:
            logging.error("无法生成配置.")

    # 保存配置
    save_xray_config(xray_config, CHECK_PATH)
    restart_xray_service('xray-check')
    time.sleep(1)

    # 调用多进程检测程序
    test_result = multi_process_test(result)
    for proxy_id, result in test_result.items():
        proxy = Conver.query.filter_by(id=proxy_id).first()
        if result == 'Inactive':
            proxy.status = 'Inactive'
        else:
            # 使用正则表达式去除 ANSI 转义序列
            result = re.sub(r'\x1b\[[0-9;]*m', '', result)
            # 尝试解析JSON结果
            try:
                ip_info = json.loads(result, strict=False)
                if ip_info.get('ip'):
                    proxy.real_ip = ip_info.get('ip', '')
                    proxy.country = ip_info.get('country', '')
                    proxy.city = ip_info.get('city', '')
                    proxy.status = 'Active'  # 更新status为'active'
                elif ip_info.get('query'):
                    proxy.real_ip = ip_info.get('query', '')
                    proxy.country = ip_info.get('country', '')
                    proxy.city = ip_info.get('city', '')
                    proxy.status = 'Active'  # 更新status为'active'
            except json.JSONDecodeError as e:
                proxy.node_ip = result
                proxy.status = 'Active'

        db.session.commit()

def conversion_services():
    # 解压文件
    xray_tar_path = '/usr/local/xos/static/xray.tar.gz'  # 使用相对路径，确保 xray.tar.gz 与脚本在同一目录下
    extract_path = '/usr/local/xos/'

    # 检查目标文件是否存在
    if os.path.exists(xray_tar_path):
        # 检查解压路径是否存在
        if not os.path.exists(extract_path):
            # 解压文件到指定路径
            with tarfile.open(xray_tar_path, 'r') as tar:
                tar.extractall(path=extract_path)

    conversion_service = """
[Unit]
Description=Conver Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=xray
Group=xray
PIDFile=/run/conversion.pid
ExecStart=/usr/local/xos/xray/xray -config /usr/local/xos/xray/conversion.json
Restart=always
RestartSec=5
StartLimitInterval=0
#Restart=on-failure
# Don't restart in the case of configuration error
RestartPreventExitStatus=25
LimitNPROC=500
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
    """
    # 定义服务名
    service_name = "conversion.service"
    # 检查服务是否已经在运行
    result = subprocess.run(['systemctl', 'is-active', service_name], stdout=subprocess.PIPE)
    if result.returncode == 0:
        logging.info(f"服务 {service_name} 已经在运行，跳过执行")
        subprocess.run(['systemctl', 'restart', service_name])
    else:
        # 写入服务文件
        with open("/etc/systemd/system/conversion.service", "w") as f:
            f.write(conversion_service)
        subprocess.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'enable', service_name])
        subprocess.run(['systemctl', 'start', service_name])

def conversion_start(data):
    conversion_config = {"log": {"loglevel": "warning","error": "/var/log/xray/conversion_error.log","access": "/var/log/xray/conversion_access.log"},"inbounds": [], "outbounds": [], "routing": {"rules": []}}
    if data:
        for item in data:
            protocol = item.get('protocol')
            tag = item.get('tag')
            inbound_connections = item.get('inbound_connections').strip()
            outbound_connections = item.get('outbound_connections').strip()

            # 在这里对每个连接进行处理
            inbound = generate_conversion_inbound(inbound_connections,tag)
            decode_data, protocol = decode_proxy_link(outbound_connections)
            outbound = generate_node_outbound(decode_data, tag, protocol)
            conversion_config["inbounds"].append(inbound)
            conversion_config["outbounds"].append(outbound)
            # 添加路由规则到conversion_config中的routing下的rules列表中
            tag_rule = {
                "type": "field",
                "inboundTag": tag,
                "outboundTag": tag
            }
            conversion_config["routing"]['rules'].append(tag_rule)
    else:
        logging.warning('请添加待转换协议')
    save_xray_config(conversion_config, "/usr/local/xos/xray/conversion.json")
    conversion_services()


def extract_conversion_data(country=None, city=None, inbound_protocol=None, outbound_protocol=None, status=None):
    query = Conver.query  # 创建查询对象

    # 根据条件过滤数据
    if country:
        query = query.filter(Conver.country.ilike(f"%{country}%"))

    if city:
        query = query.filter(Conver.city.ilike(f"%{city}%"))

    if inbound_protocol:
        query = query.filter(Conver.inbound_protocol == inbound_protocol)

    if status:
        # 使用 ilike 执行大小写不敏感的模糊匹配
        query = query.filter(Conver.status.ilike(status))

    if outbound_protocol:
        query = query.filter(Conver.outbound_protocol == outbound_protocol)

    # 如果没有传递任何条件，则返回全部数据
    if not (country or city or inbound_protocol or outbound_protocol or status):
        results = query.all()

    else:
        # 获取满足条件的数据
        results = query.all()

    return results
