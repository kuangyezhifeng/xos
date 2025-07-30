# -*- coding: utf-8 -*-
from flask import redirect, url_for, flash
from urllib.request import urlopen
from urllib.parse import parse_qs, urlparse, unquote
from base64 import urlsafe_b64decode
from threading import Thread
from app.models import *
from collections import OrderedDict
import subprocess
import re
import base64
import time
import json
import tarfile
import os
import random
import ipaddress
import logging
import socket

# 配置你的操作日志
logging.basicConfig(
    filename='/var/log/xos.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 屏蔽 Flask 的 HTTP 访问日志
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('werkzeug').propagate = False

# xray配置文件路径
CONFIG_PATH = '/usr/local/xos/xray/config.json'
CHECK_PATH = '/usr/local/xos/xray/xray-check.json'
HYSTERIA2_FOLDER = '/etc/hysteria2/'
XRAY = '/etc/systemd/system/xray.service'
XRAY_CHECK = '/etc/systemd/system/xray-check.service'
INVALID_URL_MESSAGE = "无效的连接URL"
EXISTING_OUTBOUND_MESSAGE = "已存在相同的出站配置"
TPROXY_PORT = 12345
TPROXY_IP = '127.0.0.1'
test_result = {}
update_in_progress = False

def update_handler():
    global update_in_progress
    # 创建备份目录的路径
    backup_dir_name = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    backup_dir_path = os.path.join('/xos', backup_dir_name)
    try:
        # 检查更新操作是否正在进行中，如果是则直接返回
        if update_in_progress:
            return

        # 标记更新操作已开始
        update_in_progress = True
        # 如果备份目录不存在，则创建它
        if not os.path.exists(backup_dir_path):
            os.makedirs(backup_dir_path)

        # 使用 rsync 命令备份源目录到备份目录，并替换目标目录中的文件
        subprocess.run(["rsync", "-av", "--delete", "/usr/local/xos/", backup_dir_path])
        logging.info(f"✅xos 备份成功，路径: {backup_dir_path}")

        subprocess.run(["rm", "-rf", "/tmp/xos"])
        # 克隆仓库到本地
        clone_command = "git clone https://github.com/kuangyezhifeng/xos /tmp/xos"
        logging.info("已克隆更新文件至本地")
        subprocess.run(clone_command, shell=True)

        # 执行系统命令 rsync，将 /tmp/xos 目录同步到 /usr/local/xos 目录，仅替换已存在的文件
        subprocess.run(["rsync", "-av", "/tmp/xos/", "/usr/local/xos/"])
        logging.info("xos文件更新已完成")

        # 进入虚拟环境并重装模块
        activate_command = "source /usr/local/flask/bin/activate && pip install -r /usr/local/xos/requirements.txt"
        subprocess.run(activate_command, shell=True, executable="/bin/bash")
        logging.info("flask模块检查并安装完毕")

        # 添加可执行权限
        subprocess.run(["chmod", "+x", "/usr/local/xos/xray/hysteria2"])
        subprocess.run(["chmod", "+x", "/usr/local/xos/xray/xray"])
        subprocess.run(["chmod", "+x", "/usr/local/xos/static/xos.sh"])

        # 创建一个at任务，延迟1分执行xos.sh脚本
        start_xos1 = 'echo "/usr/local/xos/static/xos.sh" | at now + 1 minutes'
        start_xos2 = 'echo "/usr/local/xos/static/xos.sh" | at now + 2 minutes'
        stop_xos1 = 'pkill -f app.py'
        stop_xos2 = 'pkill -f app.py'
        os.system(start_xos1)
        os.system(start_xos2)
        os.system(stop_xos1)
        os.system(stop_xos2)
        logging.info("xos面板重启完成")

    except Exception as e:
        logging.error(f"更新 xos 项目失败：{e}")
    finally:
        subprocess.run("pkill -f app.py", shell=True)
        logging.info("xos 项目更新成功")
        # 标记更新操作已完成
        update_in_progress = False


def create_fwmark_rule_and_local_route():
    # 检查是否存在规则
    ip_rule = f"ip rule show"
    if 'lookup 100' in subprocess.getstatusoutput(ip_rule)[1]:
        logging.info("IP路由规则已经存在.")
    else:
        subprocess.run(['ip', 'rule', 'add', 'fwmark', '0x40/0xc0', 'table', '100'], timeout=10)
        logging.info("规则添加成功.")

    route_rule = f"ip route add local 0.0.0.0/0 dev lo table 100"
    subprocess.getstatusoutput(route_rule)
    if ' File exists' not in subprocess.getstatusoutput(route_rule)[1]:
        logging.info("XOS透明路由规则已经添加.")



def reset_transparent_proxy_config():
    try:
        # 清除原有规则
        subprocess.run('iptables -F -t mangle', shell=True)

        # 创建不存在的链
        for chain in ['TP_MARK', 'TP_OUT', 'TP_PRE', 'TP_RULE']:
            subprocess.run(f'iptables -t mangle -N {chain} 2>/dev/null || true', shell=True)

        # === 入口链关联 ===
        subprocess.run('iptables -t mangle -A PREROUTING -j TP_PRE; iptables -t mangle -A OUTPUT -j TP_OUT', shell=True)

        # === 标记新连接 (TCP + UDP) ===
        subprocess.run(
            'iptables -t mangle -A TP_MARK -m conntrack --ctstate NEW -p tcp -j MARK --set-xmark 0x40/0x40; '
            'iptables -t mangle -A TP_MARK -m conntrack --ctstate NEW -p udp -j MARK --set-xmark 0x40/0x40; '
            'iptables -t mangle -A TP_MARK -j CONNMARK --save-mark', shell=True)

        # === TP_OUT 链 (处理本地发出的流量) ===
        subprocess.run(
            'iptables -t mangle -A TP_OUT -m owner --uid-owner 1001 -j RETURN; '
            'iptables -t mangle -A TP_OUT -m mark --mark 0x80/0x80 -j RETURN; '
            'iptables -t mangle -A TP_OUT -m addrtype --src-type LOCAL ! --dst-type LOCAL -j TP_RULE', shell=True)

        # === TP_PRE 链 (处理外部流量) ===
        subprocess.run(
            'iptables -t mangle -A TP_PRE -m mark --mark 0x80/0x80 -j RETURN; '
            'iptables -t mangle -A TP_PRE -i lo -m mark ! --mark 0x40/0xc0 -j RETURN; '
            'iptables -t mangle -A TP_PRE -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j TP_RULE; '
            'iptables -t mangle -A TP_PRE -m mark --mark 0x40/0xc0 -p tcp -j TPROXY --on-port 12345 --on-ip 127.0.0.1; '
            'iptables -t mangle -A TP_PRE -m mark --mark 0x40/0xc0 -p udp -j TPROXY --on-port 12345 --on-ip 127.0.0.1', shell=True)

        # === TP_RULE 链 (处理具体规则) ===
        subprocess.run(
            'iptables -t mangle -A TP_RULE -j CONNMARK --restore-mark; '
            'iptables -t mangle -A TP_RULE -m mark --mark 0x40/0xc0 -j RETURN; '
            'iptables -t mangle -A TP_RULE -i docker+ -j RETURN; '
            'iptables -t mangle -A TP_RULE -i br+ -j RETURN; '
            'iptables -t mangle -A TP_RULE -i veth+ -j RETURN; '
            'iptables -t mangle -A TP_RULE -i ppp+ -j RETURN; '
            'iptables -t mangle -A TP_RULE -p udp --dport 53 -j TP_MARK; '
            'iptables -t mangle -A TP_RULE -p tcp --dport 53 -j TP_MARK; '
            'iptables -t mangle -A TP_RULE -m mark --mark 0x40/0xc0 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 10.0.0.0/8 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 100.64.0.0/10 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 169.254.0.0/16 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 172.16.0.0/12 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 192.168.0.0/16 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 224.0.0.0/4 -j RETURN; '
            'iptables -t mangle -A TP_RULE -d 240.0.0.0/4 -j RETURN; '
            'iptables -t mangle -A TP_RULE -j TP_MARK', shell=True)

        logging.info("重置透明代理配置成功。")

    except Exception as e:
        logging.error("重置透明代理配置时发生错误：" + str(e))
    # 添加xray用户安装hysteria2程序
    xray_useradd()

def restart_xos_service():
    """
    重启 xos 面板服务
    返回包含状态、输出和带图标的消息（使用 ✅❌）
    """
    result = subprocess.run(
        ['systemctl', 'restart', 'xos.service'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    success = result.returncode == 0

    if success:
        message = '✅ xos.service 重启成功'
        logging.info(message)
    else:
        message = f'❌ xos.service 重启失败，错误码: {result.returncode}'
        logging.error(message)
        if result.stderr.strip():
            logging.error(f'stderr: {result.stderr.strip()}')
        if result.stdout.strip():
            logging.info(f'stdout: {result.stdout.strip()}')

    return {
        'success': success,
        'message': message,
        'stdout': result.stdout.strip(),
        'stderr': result.stderr.strip()
    }

def restore_system_state():
    socat_count = db.session.query(RelayConnection).filter_by(status='1').count()
    # 执行带有管道的命令
    command = "ps -ef | grep socat | wc -l"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # 获取输出并转换为整数
    output, error = process.communicate()
    socat_running_count = int(output.decode().strip())
    if socat_running_count < socat_count:
        logging.info("socat 进程数量,开始启动中转进程: %d", socat_count)
        relay_connections = RelayConnection.query.all()
        for relay_connection in relay_connections:
            process_single_relay(relay_connection, "on")

    create_fwmark_rule_and_local_route()
    logging.info("XOS面板启动重置路由和标记规则")
    # 执行命令获取输出
    command = "iptables -vnL -t mangle | wc -l"
    output = subprocess.check_output(command, shell=True)

    # 获取输出并转换为整数
    iptables_count = int(output.strip())
    # 检查行数是否小于 58
    if iptables_count < 58:
        reset_transparent_proxy_config()
        # 输出 iptables 行数
        logging.info("XOS面板启动重置透明代理规则: %d", iptables_count)


def xray_useradd():
    # 定义 xray 用户名
    xray_username = 'xray'

    # 检查用户是否存在
    try:
        subprocess.check_output(['id', xray_username], stderr=subprocess.STDOUT)
        logging.info(f"✅用户 '{xray_username}' 已存在。")
    except subprocess.CalledProcessError:
        # 如果用户不存在，则创建用户
        subprocess.run(['useradd', '-m', '-s', '/bin/bash', xray_username])
        # 改变目录所有权
        logging.info(f"✅用户 '{xray_username}' 创建成功。")

    # 获取用户的 uid
    uid_output = subprocess.check_output(['id', '-u', xray_username]).decode().strip()
    user_uid = int(uid_output)

    # 添加 iptables 规则
    iptables_rule = f"iptables -t mangle -I TP_OUT -m owner --uid-owner {user_uid} -j RETURN"

    try:
        subprocess.run(iptables_rule, shell=True, check=True)
        logging.info(f"✅为用户 '{xray_username}' (UID: {user_uid}) 添加 iptables 规则成功。")
    except subprocess.CalledProcessError as e:
        logging.error(f"添加 iptables 规则时发生错误: {e}")


# 设置启停标志
def set_tag(proxies):
    if proxies.flag == 1:
        proxies.flag = 0
        db.session.commit()
    else:
        proxies.flag = 1
        db.session.commit()



def set_config(proxies):
    if proxies.protocol == 'hysteria2':
        if proxies.flag == 1:
            xray_node_outbound_remove(proxies.tag)
            uninstall_hysteria2_service(proxies.tag)
        else:
            xray_node_outbound_add(proxies.proxy_url, proxies.tag)
        set_tag(proxies)

    else:
        if proxies.flag == 1:
            xray_node_outbound_remove(proxies.tag)
        else:
            xray_node_outbound_add(proxies.proxy_url, proxies.tag)
        set_tag(proxies)


def switch_proxy_mode(mode):
    if mode == "local":
        sed_command = ['sed', '-i', 's/^#*net\\.ipv4\\.ip_forward.*/net.ipv4.ip_forward = 1/', '/etc/sysctl.conf']
        sed_process = subprocess.run(sed_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['iptables', '-F', '-t', 'mangle'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        Xos_config.query.update({"proxy_mode": False})
    else:
        sed_command = ['sed', '-i', 's/^#*net\\.ipv4\\.ip_forward.*/net.ipv4.ip_forward = 0/', '/etc/sysctl.conf']
        sed_process = subprocess.run(sed_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        create_fwmark_rule_and_local_route()
        reset_transparent_proxy_config()
        Xos_config.query.update({"proxy_mode": True})

    # 如果 sed 命令执行成功，则继续执行 sysctl 命令
    if sed_process.returncode == 0:
        sysctl_process = subprocess.run(['sysctl', '-p'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # 如果 sysctl 命令也执行成功，则提交数据库更改
        if sysctl_process.returncode == 0:
            logging.info('sysctl 命令执行成功')
            # 提交修改到数据库
            db.session.commit()
            logging.info(f'切换代理模式{mode}成功')
        else:
            logging.error('切换代理模式{mode}失败')


def switch_proxy_share(proxy_share):
    share_config = [
        {
            "port": 1987,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "57969d78-64a6-4aed-dcb9-94c2296cabfd",
                        "alterId": 0
                    }
                ],
                "disableInsecureEncryption": False
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
            "tag": "vmess",
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "port": 1988,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
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
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"]
            }
        }
    ]
    # 先加载当前的 xray 配置
    xray_config = load_xray_config(CONFIG_PATH)

    # 如果要启用分享代理
    if proxy_share == "enable":
        # 检查要添加的配置是否已存在
        for config in share_config:
            if config not in xray_config["inbounds"]:
                # 如果不存在，则将其添加到 xray 配置中
                xray_config["inbounds"].append(config)
        # 更新数据库中的代理分享字段为 True
        Xos_config.query.update({"proxy_share": True})
        db.session.commit()
        logging.info("启用局域网分享成功")

    else:
        for config in share_config:
            if config in xray_config["inbounds"]:
                xray_config["inbounds"].remove(config)

        Xos_config.query.update({"proxy_share": False})
        db.session.commit()
        logging.info("禁用局域网分享成功")

    save_xray_config(xray_config, CONFIG_PATH)

def set_page_number(number):
    # 构造 sed 命令
    sed_command = "sed -i 's/PER_PAGE = .*/PER_PAGE = {}/g' /usr/local/xos/app.py".format(number)
    subprocess.run(sed_command, shell=True)

    at_command = 'echo "/usr/local/xos/static/xos.sh" | at now + 1 minutes'
    subprocess.run(at_command, shell=True)

    # 执行数据库更新操作
    Xos_config.query.update({"page_rows": number})
    db.session.commit()
    logging.info("设置页数显示行数完成,等待重启XOS面板")


# 批量测试判断端口有无在本地使用
def is_local_port_in_use(port):
    command = "ss -ntlua | grep {}".format(port)
    try:
        # 执行系统命令并获取输出
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        # 解析命令输出，检查是否有监听端口的行
        output = output.decode('utf-8')
        lines = output.strip().split('\n')
        for line in lines:
            if line.strip() != '':
                # 如果找到监听端口的行，则返回True
                return True
    except subprocess.CalledProcessError:
        # 如果命令执行失败，则返回False
        return False
    # 如果没有找到监听端口的行，则返回False
    return False

def reset_xray_services():
    # 使用 os.system 创建文件夹
    os.system("mkdir -p /usr/local/xos/xray")
    try:
        xray_tar_path = '/usr/local/xos/static/xray.tar.gz'  # 使用相对路径，确保 xray.tar.gz 与脚本在同一目录下
        extract_path = '/usr/local/xos/'

        with tarfile.open(xray_tar_path, 'r') as tar:
            tar.extractall(path=extract_path)

        # 创建日志目录
        log_directory = '/var/log/xray'
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)

    except Exception as e:
        logging.error("安装配置Xray服务异常：%s", str(e))

    # Xray Service
    xray_service_content = """
[Unit]
Description=Xray Service
After=network.target
Wants=network.target

[Service]
Type=simple
PIDFile=/run/xray.pid
ExecStart=/usr/local/xos/xray/xray -config /usr/local/xos/xray/config.json
Restart=always
RestartSec=5
StartLimitInterval=0
#Restart=on-failure
# Don't restart in the case of configuration error
RestartPreventExitStatus=23
LimitNPROC=500
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
    """

    # Xray Check Service
    xray_check_service_content = """
[Unit]
Description=Xray Check Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=xray
Group=xray
PIDFile=/run/xray-check.pid
ExecStart=/usr/local/xos/xray/xray -config /usr/local/xos/xray/xray-check.json
Restart=always
RestartSec=5
StartLimitInterval=0
#Restart=on-failure
# Don't restart in the case of configuration error
RestartPreventExitStatus=23
LimitNPROC=500
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
    """

    # 写入服务文件
    save_xray_config(xray_service_content, XRAY)
    save_xray_config(xray_check_service_content, XRAY_CHECK)

    # 启用服务
    # 重新载入服务
    subprocess.run(['systemctl', 'daemon-reload'])

    # 启用服务
    subprocess.run(['systemctl', 'enable', 'xray.service'])
    subprocess.run(['systemctl', 'enable', 'xray-check.service'])

    # 重启服务
    subprocess.run(['systemctl', 'restart', 'xray.service'])
    subprocess.run(['systemctl', 'restart', 'xray-check.service'])

    logging.info("Xray服务重置成功。")


def is_xray_enabled():
    command = "systemctl is-enabled xray.service"
    result = subprocess.getstatusoutput(command)
    if result[0] == 0:
        return True
    else:
        return False


def gateway_route_config():
    target_ips = []

    # 获取所有已启用access_ip
    target_ips = ProxyDevice.query.with_entities(
        ProxyDevice.access_ip, ProxyDevice.tag, ProxyDevice.gateway
    ).filter(
        ProxyDevice.flag == 1
    ).all()

    # 获取所有gateway为1的值
    selected_target_ips = set((ip, tag) for ip, tag in ProxyDevice.query.filter(
        (ProxyDevice.gateway == 1)).with_entities(ProxyDevice.access_ip, ProxyDevice.tag).all())

    target_ips_with_selection = [
        {'ip': ip, 'tag': tag, 'selected': (ip, tag) in selected_target_ips}
        for ip, tag, gateway in target_ips
    ]

    return target_ips_with_selection


def gateway_route_savedb(selected_target_ips):
    # 清除所有记录的 gateway 字段
    ProxyDevice.query.update({"gateway": None})

    # 将所有选中的 access_ip 对应的记录的 gateway 字段设置为 1
    for combined_ip_tag in selected_target_ips:
        ip, tag = combined_ip_tag.split('-')
        ProxyDevice.query.filter_by(access_ip=ip, tag=tag).update(
            {"gateway": 1},
            synchronize_session=False
        )

    db.session.commit()


def gateway_route_set():
    # 使用 load_xray_config 函数加载 xray_config
    xray_config = load_xray_config(config_path=CONFIG_PATH)
    # 添加网关路由
    gateway_rule = {
        "type": "field",
        "balancerTag": "balancer",
        "port": "0-65535"
    }
    rules_list = xray_config["routing"].get("rules", [])

    # 获取选中的 access_ip 对应的 tag 值
    tags = ProxyDevice.query.filter_by(gateway=1).with_entities(ProxyDevice.tag).all()

    # 无论 tags 是否为空，先清除旧的 balancers 配置 ✅
    xray_config["routing"]["balancers"] = []


    # 如果 tags 为空，移除已存在的 "balancers" 和 "rules"
    if not tags:
        xray_config.pop("observatory", None)

        # 移除默认网关路由规则
        if gateway_rule in rules_list:
            rules_list.remove(gateway_rule)

        # 移除DNS代理设置
        for outbound in xray_config.get("outbounds", []):
            if outbound.get("tag") == "dns-out":
                if "proxySettings" in outbound:
                    del outbound["proxySettings"]

        else:
            logging.info("tags 为空，但指定规则不在列表中")

        logging.info("默认网关取消, 清理 balancers 和 rules  dns proxy 成功")
        save_xray_config(xray_config, config_path=CONFIG_PATH)

    else:
        # 将数据库中查询到的 tags 直接替换为新的标签值
        replaced_tags = [tag for tag, in tags]

        # 如果 tags 为空，移除已存在的 "balancers" 和 "rules"
        if not tags:
            xray_config["routing"].pop("balancers", None)
            xray_config.pop("observatory", None)

        balancer = {
            "tag": "balancer",
            "selector": replaced_tags,
            "strategy": {
                "type": "roundRobin"
            },
            "fallbackTag": "direct"
        }
        # 添加 observatory
        xray_config["observatory"] = {
            "subjectSelector": replaced_tags,
            "probeUrl": "https://www.google.com/generate_204",
            "probeInterval": "10s",
            "enableConcurrency": True
        }
        # 添加新的 "balancers" 到列表中
        xray_config["routing"].setdefault("balancers", []).append(balancer)

        xray_config["routing"].setdefault("rules", []).append(gateway_rule) if gateway_rule not in rules_list else None

        # 当默认网关不为空的时候,给DNS添加代理设置
        for outbound in xray_config.get("outbounds", []):
            if outbound.get("tag") == "dns-out":
                if "proxySettings" in outbound:
                    outbound["proxySettings"].update({"tag": replaced_tags[0]})
                else:
                    outbound["proxySettings"] = {"tag": replaced_tags[0]}

        save_xray_config(xray_config, config_path=CONFIG_PATH)

        logging.info("设置代理网关成功")


def reset_xray_config():
    # 将所有 flag 为 1 的记录的 flag 字段更新为 0
    db.session.query(ProxyDevice).filter(ProxyDevice.flag == 1).update({'flag': 0}, synchronize_session=False)

    # 将所有 gateway 为 '是' 的记录的 gateway 字段更新为 '否'
    db.session.query(ProxyDevice).filter(ProxyDevice.gateway == 1).update({'gateway': 0},
                                                                          synchronize_session=False)
    # 提交更改
    db.session.commit()

    # Xray Config
    xray_config_content = {
        "log": {
            "loglevel": "warning",
            "error": "/var/log/xray/error.log",
            "access": "/var/log/xray/access.log"
        },
        "inbounds": [
            {
                "tag": "all-in",
                "port": 12345,
                "protocol": "dokodemo-door",
                "settings": {
                    "network": "tcp,udp",
                    "udpIdleTimeout": 600,
                    "followRedirect": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                },
                "streamSettings": {
                    "sockopt": {
                        "tproxy": "tproxy",
                        "udpFragment": True
                    }
                }
            }
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIP"
                },
                "streamSettings": {
                    "sockopt": {
                        "mark": 128
                    }
                }
            },
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {
                    "address": "8.8.8.8"
                },
                "streamSettings": {
                    "sockopt": {
                        "mark": 128
                    }
                }
            }
        ],
        "dns": {
            "hosts": {
                "dns.google": ["8.8.8.8", "8.8.4.4"]
            },
            "servers": [
                "8.8.8.8",
                "1.1.1.1",
                {
                    "address": "114.114.114.114",
                    "port": 53,
                    "domains": ["geosite:cn"],
                    "expectIPs": ["geoip:cn"]
                },
                {
                    "address": "223.5.5.5",
                    "port": 53,
                    "domains": ["geosite:cn"],
                    "expectIPs": ["geoip:cn"]
                }
            ]
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["all-in"],
                    "port": 53,
                    "outboundTag": "dns-out"
                },
                {
                    "type": "field",
                    "ip": [
                        "127.0.0.1/8",
                        "192.168.0.0/16",
                        "172.16.0.0/16",
                        "10.0.0.0/8",
                        "114.114.114.114",
                        "223.5.5.5",
                        "geoip:private"
                    ],
                    "outboundTag": "direct"
                }
            ]
        }
    }


    # Xray Check Config
    xray_check_config_content = {
        "inbounds": [
            {
                "tag": "1233",
                "port": 1233,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
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
                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "AsIs"
                },
                "streamSettings": {
                    "sockopt": {
                        "mark": 128
                    }
                }
            },
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {
                    "address": "8.8.8.8"
                },
                "proxySettings": {
                    "tag": "proxy"
                },
                "streamSettings": {
                    "sockopt": {
                        "mark": 128
                    }
                }
            },
            {
                "tag": "proxy",
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": "kriepl02.awsstudent.com",
                            "port": 24100,
                            "users": [
                                {
                                    "id": "5cfc2e53-eff1-3f51-a9d3-6244ba61a1f6",
                                    "security": "auto"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "sockopt": {
                        "mark": 128,
                        "tcpFastOpen": True
                    },
                    "wsSettings": {
                        "path": "/6",
                        "headers": {
                            "Host": "live.bilibili.com"
                        }
                    }
                }
            }
        ],
        "dns": {
            "hosts": {
                "dns.google": [
                    "8.8.8.8",
                    "8.8.4.4"
                ]
            },
            "servers": [
                "8.8.8.8",
                "1.1.1.1"
            ]
        },
        "routing": {
            "domainStrategy": "IPOnDemand",
            "domainMatcher": "mph",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [
                        "all-in"
                    ],
                    "port": 53,
                    "outboundTag": "dns-out"
                },
                {
                    "type": "field",
                    "ip": [
                        "8.8.8.8",
                        "1.1.1.1"
                    ],
                    "outboundTag": "proxy"
                },
                {
                    "type": "field",
                    "ip": [
                        "geoip:private",
                        "127.0.0.1/8",
                        "192.168.1.0/24"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "inboundTag": [
                        "1233"
                    ],
                    "outboundTag": "proxy"
                }
            ]
        }
    }

    save_xray_config(xray_config_content, CONFIG_PATH)
    save_xray_config(xray_check_config_content, CHECK_PATH)


def proxy_lan_share():
    share_config = [
        {
            "port": 1987,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "57969d78-64a6-4aed-dcb9-94c2296cabfd",
                        "alterId": 0
                    }
                ],
                "disableInsecureEncryption": False
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
            "tag": "vmess",
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "port": 1988,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
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
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"]
            }
        }
    ]

    xray_config = load_xray_config(CONFIG_PATH)
    xray_config["inbounds"].extend(share_config)  # 使用 extend 方法将列表中的字典添加到 xray_config["inbounds"] 中
    save_xray_config(xray_config, CONFIG_PATH)


def uninstall_hysteria2_service(tag):
    # 停止服务
    subprocess.run(["sudo", "systemctl", "stop", f"{tag}.service"])
    # 禁用服务
    subprocess.run(["sudo", "systemctl", "disable", f"{tag}.service"])
    # 删除服务文件
    service_file_path = f"/etc/systemd/system/{tag}.service"
    subprocess.run(["sudo", "rm", service_file_path])
    subprocess.run(["sudo", "rm", f"/etc/hysteria2/{tag}.json"])
    # 重新加载 Systemd
    subprocess.run(["sudo", "systemctl", "daemon-reload"])
    logging.info(f"✅已卸载hysteria2服务: {tag}")

    return True

"""
decode_vmess_link 函数
功能描述：

decode_vmess_link 函数用于解码 Vmess 链接，将经过 Base64 编码的链接解析为 JSON 格式的配置信息。函数接受一个参数：

proxy_url: 经过 Base64 编码的 Vmess 链接。
操作步骤：

使用 base64.urlsafe_b64decode 函数解码经过 Base64 编码的 Vmess 链接。在解码之前，移除链接中可能的额外字符（'='）以适应 Base64 解码的要求。
使用 decode 函数将解码后的字节序列转换为 UTF-8 编码的字符串。
尝试使用 json.loads 函数将解码后的字符串解析为 JSON 格式的配置信息。
如果解析过程中发生错误（如 JSON 解析错误、Unicode 解码错误等），记录错误日志并返回 None。
返回值：

如果解码和解析成功，返回一个包含 Vmess 配置信息的字典。
如果解码或解析过程中发生错误，返回 None 或者适当的错误值，表示解码失败。
注意： 该函数在处理解码和解析错误时进行了错误日志记录，以便在出现问题时进行调试。
"""


def decode_vmess_link(proxy_url):
    try:
        decoded_vmess = base64.urlsafe_b64decode(proxy_url[8:] + '=' * (4 - len(proxy_url) % 4)).decode('utf-8')
        return json.loads(decoded_vmess)

    except (TypeError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logging.error(f"解码 vmess 链接时发生错误: {e}")
        return None  # 返回 None 或者适当的错误值，表示解码失败


def encode_vmess_link(vmess_json):
    try:
        vmess_str = json.dumps(vmess_json)
        vmess_bytes = vmess_str.encode('utf-8')
        return 'vmess://' + base64.b64encode(vmess_bytes).decode('utf-8')
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return None


def extract_base64(data):
    start_index = data.find("vmess://")
    if start_index == -1:
        return None

    vmess_data = data[start_index + len("vmess://"):]
    return vmess_data


def parse_vmess_subscription(subscribe_url):
    try:
        return_content = urlopen(subscribe_url).read()
        share_links = urlsafe_b64decode(return_content).decode("utf-8").splitlines()
    except Exception:
        logging.error(f'订阅连接异常: {subscribe_url}')
        return []

    configs = []

    for share_link in share_links:
        try:
            vmess_data = extract_base64(share_link)
            if vmess_data is None:
                continue

            decoded_data = urlsafe_b64decode(
                vmess_data + "=" * (4 - len(vmess_data) % 4)
            ).decode("utf-8")

            json_data = json.loads(decoded_data)

            if json_data.get("v") == "2":
                configs.append(share_link)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            continue

    return configs


def decode_vless_link(vless_url):
    # 正则表达式模式：匹配 vless 链接的两种格式
    pattern = r'vless://([^@]+)@([^:/?#]+):(\d+)([^#]*)(?:#([^?]+))?'

    # 匹配正则表达式
    match = re.match(pattern, vless_url)

    if match:
        # 提取 user_info 和地址、端口
        user_info, ip, port, query_fragment, email = match.groups()

        # 判断 email 是否为 None
        if email:
            email_prefix = email.split('@')[0]
        else:
            email_prefix = ''

        # 解析 query 参数
        query_params = dict(re.findall(r'&?([^=]+)=([^&]*)', query_fragment)) if query_fragment else {}

        # 获取特定的字段并解码 path 和 spx
        vless_info = {
            'uuid': user_info,
            'ip': ip,
            'port': int(port),
            'encryption': query_params.get('encryption', 'none'),
            'flow': query_params.get('flow', ''),
            'security': query_params.get('security', 'reality'),
            'sni': query_params.get('sni', ''),
            'fp': query_params.get('fp', ''),
            'pbk': query_params.get('pbk', ''),
            'type': query_params.get('type', 'tcp'),
            'headerType': query_params.get('headerType', 'none'),
            'email': email_prefix,
            'path': unquote(query_params.get('path', '')),  # URL 解码
            'spx': unquote(query_params.get('spx', '/')),  # 默认值为 '/'
            'sid': query_params.get('sid', ''),
        }

        return vless_info

    return None

def custom_unquote(string):
    return string.replace('%2F', '/')


def decode_trojan_link(trojan_url):
    result = {}
    # Check if URL starts with "trojan://"
    if not trojan_url.startswith("trojan://"):
        return None

    # Remove the protocol header
    trojan_url = trojan_url.replace("trojan://", "")

    # Check if "@" and "?" exist in the URL
    if "@" not in trojan_url or "?" not in trojan_url:
        return None

    server_and_port = trojan_url.split("@")[1].split("?")[0]
    server, port = server_and_port.split(":")
    password = trojan_url.split("@")[0]

    # Check if "?" exists
    if "?" not in trojan_url:
        return None

    security = alpn = type_ = header_type = None

    query_params = trojan_url.split("?")[1].split("&")
    for param in query_params:
        key_value = param.split("=")
        if len(key_value) != 2:
            continue
        key, value = key_value
        if key == "security":
            security = value
        elif key == "alpn":
            alpn = custom_unquote(value)  # 自定义解码alpn值
        elif key == "type":
            type_ = value
        elif key == "headerType":
            header_type = value

    if None in (security, type_):
        return None

    trojan_json = {
        "password": password,
        "server": server,
        "port": int(port),  # 将端口号转换为整数类型
        "security": security,
        "alpn": alpn,
        "type": type_,
        "header_type": header_type
    }
    return trojan_json


def decode_shadowsocks_link(ss_url):
    try:
        # 去除 "ss://" 前缀
        ss_data = ss_url.replace("ss://", "")

        # 去除 "#" 后面的内容
        ss_data = ss_data.split("#")[0]

        # 提取服务器信息和额外信息
        ss_data_parts = ss_data.split("@")
        server_info = ss_data_parts[-1]

        # 提取服务器地址和端口号
        server_address_port_parts = server_info.split(":")
        server_address = server_address_port_parts[0]
        server_port_extra = server_address_port_parts[1].split("?")[0]  # 移除可能的额外参数
        server_port = server_port_extra.split("/")[0]  # 移除可能的路径

        # 解码 Base64 部分
        base64_data = ss_data_parts[0]
        # 添加填充字符"="，直到长度是4的倍数
        missing_padding = len(base64_data) % 4
        if missing_padding != 0:
            base64_data += '=' * (4 - missing_padding)
        decoded_data = base64.b64decode(base64_data).decode("utf-8")

        # 提取加密方法和密码
        method, password = decoded_data.split(":")

        # 构建配置对象
        shadowsocks_json = {
            "method": method,
            "password": password,
            "server": server_address,
            "port": int(server_port)
        }
        return shadowsocks_json
    except Exception as e:
        logging.error(f"SHADOWSOCKS 解析错误: {e}")
        return None


def decode_hysteria2_url(hysteria2_url):
    result = {}
    # Remove the protocol header
    hysteria2_url = hysteria2_url.replace("hysteria2://", "")

    # Extract server address and port
    server_port = hysteria2_url.split("@")[1].split("?")[0]
    server, port = server_port.split(":")
    # Remove any trailing slash from the port
    port = port.rstrip('/')
    result["server"] = f"{server}:{port}"

    # Extract password
    password = hysteria2_url.split("@")[0]
    result["auth"] = password

    # Extract SNI and insecure flag
    sni_insecure_part = hysteria2_url.split("sni=")[-1].split("&")
    if len(sni_insecure_part) > 1:
        insecure_value = sni_insecure_part[1].split("=")[1]
        if insecure_value.isdigit():
            result["tls"] = {"sni": sni_insecure_part[0], "insecure": bool(int(insecure_value))}
        else:
            result["tls"] = {"sni": sni_insecure_part[0], "insecure": True}
    else:
        result["tls"] = {"sni": "", "insecure": True}

    # Extract obfs parameters
    obfs_type = None
    obfs_password = None
    if "obfs=" in hysteria2_url:
        obfs_type = hysteria2_url.split("obfs=")[1].split("&")[0]
        result["obfs"] = {"type": obfs_type}
    if "obfs-password=" in hysteria2_url:
        obfs_password = hysteria2_url.split("obfs-password=")[1].split("&")[0]
        if obfs_type:
            result["obfs"][obfs_type] = {"password": obfs_password}

    # Generate a random port number
    random_port = random.randint(60000, 65534)
    result["socks5"] = {"listen": f"0.0.0.0:{random_port}"}

    # 添加带宽配置
    result["bandwidth"] = {
        "up": "100 mbps",     # 最大上行带宽 100 Mbps
        "down": "500 mbps"    # 最大下行带宽 500 Mbps
    }

    return result


"""

decode_socks_link 函数
功能描述：

decode_socks_link 函数用于解码 Socks 链接，将经过自定义编码的链接解析为包含 Socks 配置信息的字典。函数接受一个参数：

socks_link: 经过自定义编码的 Socks 链接。
操作步骤：

使用字符串分割操作 split 拆分 Socks 链接，提取链接中的各个部分。
解析拆分后的部分，获取协议、目标 IP、目标端口、用户名和密码。
验证协议是否为 "socks"，验证端口范围是否正确，验证目标 IP 是否为有效的 IP 地址。
构造包含 Socks 配置信息的字典，包括协议、目标 IP、目标端口、用户名和密码。
如果在解码和解析的过程中出现错误，记录错误日志并返回 None。
返回值：

如果解码和解析成功，返回一个包含 Socks 配置信息的字典。
如果解码或解析过程中发生错误，返回 None，并记录错误信息。
注意： 该函数在处理解码和解析错误时进行了错误日志记录，以便在出现问题时进行调试。
"""


def decode_socks_link(socks_link):
    try:
        # 如果链接以 socks:// 开头，去掉前缀
        if socks_link.startswith('socks://'):
            socks_link = socks_link[len('socks://'):]

        # 格式: target_ip:port:username:password
        parts = socks_link.split(':', 2)  # 只拆分前两个冒号，剩下的留给用户名和密码

        # 提取协议、目标 IP 和目标端口
        protocol = 'socks'
        target_ip = parts[0]
        target_port = int(parts[1])

        # 提取用户名和密码
        remaining = parts[2].split(':', 1)  # 剩余部分再次以冒号拆分
        username = remaining[0]
        password = remaining[1] if len(remaining) > 1 else None

        # 验证协议
        if protocol.lower() != 'socks':
            raise ValueError("不支持的协议")

        # 验证端口范围
        if not (0 <= target_port <= 65535):
            raise ValueError("端口范围不正确")

        # 验证IP地址
        if not is_ip_or_domain(target_ip):
            raise ValueError("错误的域名或IP地址")

        decoded_data = {
            "protocol": protocol,
            "target_ip": target_ip,
            "target_port": target_port,
            "username": username,
            "password": password
        }
        return decoded_data

    except Exception as e:
        logging.error(f"解码 SOCKS 连接时出错: {str(e)}")
        return None

def get_all_access_ips():
    try:
        access_ips = ProxyDevice.query.with_entities(ProxyDevice.access_ip).all()
        return [ip[0] for ip in access_ips]
    except Exception as e:
        # Handle the exception based on your application's requirements
        return []


"""
node_domain_set 函数
功能描述：

node_domain_set 函数用于将域名解析后的 IP 地址添加到 Xray 配置文件中。函数接受两个参数：

ip_domain: 要解析并添加到配置文件的域名或 IP 地址。
xray_config: Xray 的配置信息。
操作步骤：

检查 ip_domain 是否为域名（而非 IP 地址）。
如果是域名，则使用 socket.gethostbyname_ex 函数解析域名，获取其对应的 IP 地址列表。
强制替换配置文件中 dns 部分的 hosts 字典中键为域名的值，更新为解析得到的 IP 地址列表。
记录成功添加或更新 IP 地址的日志信息。
"""


# 将节点域名转成IP地址
def node_domain_set(xray_config, decode_data):
    if decode_data.get('add'):
        access_ip = decode_data.get('add')
    elif decode_data.get('target_ip'):
        access_ip = decode_data.get('target_ip')
    elif decode_data.get('ip'):
        access_ip = decode_data.get('ip')
    elif decode_data.get('server'):
        access_ip = decode_data.get('server')
    else:
        logging.info('hysteria2域名解析跳过')
        return
    # 如果地址是域名，则解析域名并添加到文件中

    if access_ip and not is_ip_address(access_ip) and ":" not in access_ip:
        hostname = access_ip
        #写入 DNS 配置文件
        subprocess.run(['echo', '-e', '"nameserver 8.8.8.8\nnameserver 1.1.1.1"', '>', '/etc/resolv.conf'], shell=True)
        # 执行命令PING解析域名并获取到IP地址
        command = ['sudo', '-u', 'xray', 'ping', '-c', '1', hostname]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()
        # 解码输出
        output = output.decode('utf-8')
        # 使用正则表达式提取 IP 地址
        ip_match = re.search(r'\(([0-9.]+)\)', output)
        if ip_match:
            ip_address = ip_match.group(1)
            # 强制替换主机名对应的 IP 地址列表
            xray_config['dns']['hosts'][hostname] = ip_address
            logging.info(f"✅成功将域名 {hostname} 解析为 IP 地址: {ip_address}")
        else:
            logging.error(f"无法从 ping 输出中提取 IP 地址: {output}")

"""
node_domain_unset 函数
功能描述：

node_domain_unset 函数用于从 Xray 配置文件中移除指定域名对应的 IP 地址。函数接受两个参数：

hostname: 要移除 IP 地址的域名。
xray_config: Xray 的配置信息。
操作步骤：

检查 hostname 是否存在于配置文件的 dns 部分的 hosts 字典中。
如果存在，删除键为 hostname 的条目，并记录成功移除 IP 地址的日志信息。
如果不存在，记录域名不存在的日志信息。
"""


def node_domain_unset(hostname, xray_config):
    # 检查键是否存在
    if hostname in xray_config['dns']['hosts']:
        # 删除键
        deleted_ip_addresses = xray_config['dns']['hosts'].pop(hostname)
        logging.info(f"✅移除节点DNS {hostname} 对应的 IP 地址: {deleted_ip_addresses}")
    else:
        logging.info(f"✅{hostname} 不存在于文件中，无需删除")


"""
is_ip_address 函数
功能描述：

is_ip_address 函数用于检查输入字符串是否是合法的 IP 地址。函数接受一个参数：

access_ip: 要检查的字符串。
操作步骤：

尝试使用 ipaddress.ip_address 函数解析 access_ip。
如果解析成功，返回 True，表示是合法的 IP 地址；否则，返回 False。
"""


def is_ip_address(access_ip):
    try:
        ipaddress.ip_address(access_ip)
        return True
    except ValueError:
        return False


# 验证 IP 或域名
def is_ip_or_domain(target_ip):
    # 首先检查是否是有效的 IP 地址
    if is_ip_address(target_ip):
        return True

    # 使用正则表达式检查是否是有效的域名
    domain_pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    if domain_pattern.match(target_ip):
        return True

    # 如果都不是，则返回 False
    return False


"""

load_xray_config 函数
功能描述：

load_xray_config 函数用于从指定路径加载 Xray 的配置文件。函数接受一个参数：

config_path: 配置文件的路径。
操作步骤：

尝试使用 open 函数打开指定路径的配置文件。
如果文件不存在，记录错误日志并返回 None。
如果文件存在，尝试使用 json.load 函数加载配置文件内容。
如果加载过程中发生错误（如 JSON 解析错误），记录错误日志并返回 None。
如果加载成功，返回配置文件的 JSON 内容。
注意： 该函数在加载配置文件时处理了文件不存在和 JSON 解析错误的情况，以及其他可能导致读取配置文件失败的情况。
"""


def load_xray_config(config_path):
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"配置文件不存在: {config_path}")
        return None
    except (IOError, json.decoder.JSONDecodeError) as e:
        logging.error(f"读取配置文件时发生错误: {e}")
        return None


"""

save_xray_config 函数
功能描述：

save_xray_config 函数用于保存更新后的 Xray 配置到配置文件。函数接受两个参数：

xray_config: 包含 Xray 配置的字典。
config_path: 配置文件的路径。
操作步骤：

尝试以写入模式打开配置文件。
使用 json.dump 将 xray_config 写入文件，设置缩进为 2，确保非 ASCII 字符正常输出。
如果操作成功，返回 True，否则记录错误日志并返回 False。
返回值：

如果成功写入配置文件，返回 True。
如果写入失败，记录错误日志并返回 False。
"""


def save_xray_config(xray_config, config_path):
    try:
        if config_path in (XRAY, XRAY_CHECK):
            # 如果文件路径是指定的路径，直接写入预定义的字符串
            with open(config_path, 'w', encoding='utf-8') as file:
                file.write(xray_config)
                logging.info(f"✅写入系统服务 {config_path} 成功")
        else:
            # 否则，使用 JSON 格式保存配置
            with open(config_path, 'w', encoding='utf-8') as file:
                json.dump(xray_config, file, indent=4, ensure_ascii=False)
                logging.info(f"✅写入 {config_path} 配置成功")

        return True

    except IOError as e:
        logging.error(f"写入配置文件时发生错误: {e}")
        return False


"""
is_outbound_tag_exist 函数
功能描述：

is_outbound_tag_exist 函数用于检查指定的 outbound_tag 是否已存在于 Xray 配置中。函数接受两个参数：

xray_config: 包含 Xray 配置的字典。
outbound_tag: 待检查的出站标签。
操作步骤：

遍历 xray_config 中的所有出站配置，检查是否存在与输入的 outbound_tag 匹配的标签。
如果存在匹配的标签，返回 True，否则返回 False。
返回值：

如果存在指定的 outbound_tag，返回 True。
如果不存在，返回 False。

"""


def is_outbound_tag_exist(xray_config, outbound_tag):
    return any(outbound.get("tag") == outbound_tag for outbound in xray_config.get('outbounds', []))



"""
restart_xray_service 函数
功能描述：

restart_xray_service 函数用于重启指定的 Xray 服务。函数接受一个参数：

service_name: 要重启的 Xray 服务的名称。
操作步骤：

尝试执行重启 Xray 服务的命令，使用 subprocess.run。
如果重启成功，记录日志信息。
如果重启失败，记录错误日志信息。
返回值：

如果重启成功，记录日志信息，不返回任何值。
如果重启失败，记录错误日志信息，不返回任何值。
"""


def restart_xray_service(service_name):
    if service_name == "xray":
        # 执行重启Xray服务的命令
        gateway_route_set()
        subprocess.run(['systemctl', 'restart', service_name])
        logging.info(f"✅{service_name}服务重启成功")

    else:
        subprocess.run(['systemctl', 'restart', service_name])
        logging.info(f"✅{service_name}服务重启成功")


"""

create_node_handler 函数
功能描述：

create_node_handler 函数用于处理创建节点的请求。函数接受两个参数：

proxy_url: 要创建的代理节点的 URL。
protocol: 代理节点的协议类型，可以是 'vmess' 或 'socks5'。
操作步骤：

根据 protocol 的值，选择相应的协议解码函数（decode_vmess_link 或 decode_socks_link）对 proxy_url 进行解码，获取节点信息。
验证解码后的节点信息是否完整，包括 IP 地址等必需信息。
如果验证成功，调用 node_info_savedb 函数将节点信息保存至数据库，包括 proxy_url、protocol、access_ip 和节点注释（如果有）。
如果验证失败，使用 flash 记录错误信息，并重定向到创建节点的页面。
返回值：

如果创建成功，将信息保存到数据库，并在记录日志后返回到创建节点的页面。
如果验证失败，使用 flash 记录错误信息，并重定向到创建节点的页面。
"""


def create_node_handler(proxy_url, protocol):
    if not proxy_url.lower().startswith(("ss://", "socks://", "vmess://", "vless://", "hysteria2://","trojan://")):
        return 'ERROR'

    if protocol == "vmess":
        # 验证节点URL完整性并获取连接IP地址
        decoded_data = decode_vmess_link(proxy_url)

        if not decoded_data or "add" not in decoded_data:
            logging.error(f'无效的{protocol}协议连接', 'error')
            return redirect(url_for('create_node'))
        # 提交数据保存至数据库
        node_info_savedb(proxy_url, protocol, decoded_data.get("add"), decoded_data.get("ps"))

    elif protocol == "vless":
        decode_date = decode_vless_link(proxy_url)
        access_ip = decode_date['ip']
        node_info_savedb(proxy_url, protocol, access_ip)

    elif protocol == "socks":
        decoded_data = decode_socks_link(proxy_url)
        access_ip = decoded_data.get('target_ip')
        node_info_savedb(proxy_url, protocol, access_ip)

    elif protocol == "trojan":
        decoded_data = decode_trojan_link(proxy_url)
        access_ip = decoded_data.get('server')
        node_info_savedb(proxy_url, protocol, access_ip)

    elif protocol == "shadowsocks":
        decoded_data = decode_shadowsocks_link(proxy_url)
        access_ip = decoded_data.get('server')
        node_info_savedb(proxy_url, protocol, access_ip)

    elif protocol == "hysteria2":
        decode_data = decode_hysteria2_url(proxy_url)
        server_address = decode_data.get('server')
        # 从 server 地址中提取 IP 地址
        access_ip = server_address.split(":")[0]
        node_info_savedb(proxy_url, protocol, access_ip)


    elif protocol == 'subscribe':
        subscribe_configs = parse_vmess_subscription(proxy_url)
        for subscribe_url in subscribe_configs:
            decoded_data = decode_vmess_link(subscribe_url)
            # 提交数据保存至数据库
            node_info_savedb(subscribe_url, 'vmess', decoded_data.get("add"), decoded_data.get("ps"))



"""

node_info_savedb 函数
功能描述：

node_info_savedb 函数用于将节点信息保存到数据库。函数接受四个参数：

proxy_url: 代理 URL。
protocol: 协议类型。
access_ip: 访问 IP。
note: 备注信息。
操作步骤：

查询数据库，判断是否已存在相同的 proxy_url。如果存在，给出错误提示并返回。
生成一个唯一的标签 tag，用当前时间的格式作为标签。
创建 ProxyDevice 对象，插入数据库。
提交数据库事务，如果出错，回滚事务。
返回值：

如果成功，记录日志并返回 None。
如果 proxy_url 已存在，返回错误提示并重定向到创建节点页面。
"""


def generate_tag():
    # 获取当前时间的月日
    current_time = datetime.now().strftime("%m%d")
    # 生成6位随机数
    # random_number = str(random.randint(100000, 999999))
    random_number = str(random.randint(10000000, 99999999))
    # 将随机数附加到时间后面
    tag = current_time + random_number

    return tag


def node_info_savedb(proxy_url, protocol, access_ip, note=''):
    # 查询数据库，判断是否已存在相同的 proxy_url
    existing_proxy = ProxyDevice.query.filter_by(proxy_url=proxy_url).first()

    if existing_proxy:
        logging.info(f'代理{proxy_url} 重复添加!')
        return redirect(url_for('create_node'))

    # 提取POST的数据插入数据库
    tag = generate_tag()
    proxy_rule = ProxyDevice(proxy_url=proxy_url, access_ip=access_ip, protocol=protocol, tag=tag, note=note)
    db.session.add(proxy_rule)

    try:
        db.session.commit()
        logging.info(f"✅成功保存{protocol}节点到数据库")
    except Exception as e:
        db.session.rollback()
        logging.error(f"保存{protocol}节点到数据库时出错: {str(e)}")


"""
generate_node_outbound 函数
功能描述：

generate_node_outbound 函数用于生成出站节点的配置信息。函数接受两个参数：

decode_data: 解码后的代理配置信息。
tag: 节点的标签。
操作步骤：

根据协议类型调用相应的配置生成函数（generate_vmess_config 或 generate_socks_config）。
返回生成的配置信息。
返回值：

返回包含出站节点配置的 JSON 数据。


"""


# 生成出站的VMESS配置JSON文件
def generate_node_outbound(config, tag, protocol=None):
    if protocol == "socks":
        json_config = generate_socks_config(config, tag)
    elif protocol == "vless":
        json_config = generate_vless_config(config, tag)
    elif protocol == 'vmess':
        json_config = generate_vmess_config(config, tag)
    elif protocol == 'trojan':
        json_config = generate_trojan_config(config, tag)
    elif protocol == 'shadowsocks':
        json_config = generate_shadowsocks_config(config, tag)
    else:
        create_and_run_hysteria2(config, tag)
        json_config = generate_hysteria2_config(tag, tag)

    return json_config


def create_systemd_service(tag, json_file_path):
    service_name = f"{tag}.service"
    service_content = f"""
[Unit]
Description=Hysteria2 Client Service for {tag}
After=network.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/xos/xray/hysteria2 client -c {json_file_path}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""

    service_file_path = f"/etc/systemd/system/{service_name}"
    with open(service_file_path, 'w') as service_file:
        service_file.write(service_content)

    return service_name

def create_and_run_hysteria2(json_config, tag):
    # 构建 JSON 文件路径
    json_file_path = f'/etc/hysteria2/{tag}.json'

    # 写入 JSON 配置到文件
    with open(json_file_path, 'w') as json_file:
        json.dump(json_config, json_file, indent=4, ensure_ascii=False)
        logging.info(f'已创建配置文件: {json_file_path}')

    # # 使用 runuser 启动进程
    # command = f'runuser -l xray -c \'hysteria2 client -c {json_file_path} 2>/dev/null &\''
    # subprocess.Popen(command, shell=True)
    # 由进程模式改为服务运行模式,优点开机自己启动，离线自动恢复运行
    service_name = create_systemd_service(tag, json_file_path)
    subprocess.run(["sudo", "systemctl", "daemon-reload"])
    subprocess.run(["sudo", "systemctl", "enable", service_name])
    subprocess.run(["sudo", "systemctl", "start", service_name])
    logging.info(f'已启动 hysteria2 服务进程 ')


"""
generate_socks_config 函数
功能描述：

generate_socks_config 函数用于生成 Socks 协议的配置信息。函数接受两个参数：

config: 包含 Socks 配置的字典。
tag: 节点的标签。
操作步骤：

根据输入的配置信息，构建 Socks 配置的 JSON 数据。
判断是否存在用户名和密码，如果存在，添加到配置中。
返回值：

返回包含 Socks 配置的 JSON 数据。

"""


def generate_socks_config(config, tag):
    json_config = {
        "tag": tag,
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": config.get('target_ip', ''),
                    "port": int(config.get('target_port', 0)),
                }
            ]
        },
        "streamSettings": {
            "sockopt": {
                "mark": 128,
                "tcpFastOpen": True
            }
        }
    }

    # 判断是否存在账号密码
    user = config.get('username', '')
    password = config.get('password', '')

    if user and password:
        # 如果存在账号密码，添加到配置中
        json_config["settings"]["servers"][0]["users"] = [
            {
                "user": user,
                "pass": password
            }
        ]
    # 判断是否为127.0.0.1，如果是则不包含 "mark": 128
    if config.get('target_ip', '') == '127.0.0.1':
        del json_config["streamSettings"]["sockopt"]["mark"]

    return json_config


"""
generate_vmess_config 函数
功能描述：

generate_vmess_config 函数用于生成 Vmess 协议的配置信息。函数接受两个参数：

config: 包含 Vmess 配置的字典。
tag: 节点的标签
操作步骤：

根据输入的配置信息，构建 Vmess 配置的 JSON 数据。
如果协议是 KCP，添加相关的 KCP 设置。
如果协议是 WebSocket，添加相关的 WebSocket 设置。
返回值：

返回包含 Vmess 配置的 JSON 数据。


"""

def generate_vmess_config(config, tag):
    json_config = {
        "tag": f"{tag}",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": config.get('add', ''),
                    "port": int(config.get('port', 0)),
                    "users": [
                        {
                            "id": config.get('id', ''),
                            "security": config.get('scy', '')
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": config.get('net', ''),
            "sockopt": {
                "tcpFastOpen": True
            }
        }
    }

    # 如果 address 是 "127.0.0.1"，则不包含 "mark" 字段
    if config.get('add', '') != "127.0.0.1":
        json_config["streamSettings"]["sockopt"]["mark"] = 128

    if config['net'] == "kcp":
        json_config["streamSettings"]["kcpSettings"] = {
            "mtu": 1350,
            "tti": 50,
            "uplinkCapacity": 12,
            "downlinkCapacity": 100,
            "congestion": False,
            "readBufferSize": 2,
            "writeBufferSize": 2,
            "header": {
                "type": config.get('type', ''),
                "request": None,
                "response": None
            },
            "seed": config.get('path', '')
        }
    elif config['net'] == "ws":
        json_config["streamSettings"]["wsSettings"] = {
            "path": config.get('path', ''),
            "headers": {
                "Host": config.get('host', '')
            }
        }

    return json_config


def generate_vless_config(config, tag):
    # 获取 email 和 security 的默认值
    security = config.get('security', 'auto')

    # 初始化基础的 JSON 配置
    json_config = {
        "tag": f"{tag}",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": config.get('ip', ''),
                    "port": config.get('port', ''),
                    "users": [
                        {
                            "id": config.get('uuid', ''),
                            "encryption": "none",
                            "flow": config.get('flow', ''),
                            "security": security  # 使用 security 默认值
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",  # 默认使用 TCP
            "security": "reality",
            "realitySettings": {
                "serverName": config.get('sni', ''),
                "fingerprint": "chrome",
                "show": False,
                "publicKey": config.get('pbk', ''),
                "shortId": config.get('sid', ''),  # 设置 shortId
                "spiderX": "/"  # 默认使用 "/"
            },
            "sockopt": {
                "mark": 128,
                "tcpFastOpen": True
            },
        },
        "mux": {
            "enabled": False,
            "concurrency": -1
        }
    }

    # 根据 type 字段处理配置
    if config.get('type', '') == 'xhttp':
        json_config["streamSettings"]["network"] = "xhttp"
        json_config["streamSettings"]["xhttpSettings"] = {
            "path": config.get('path', ''),
        }
        # 如果有 spx 字段，则加入 spx 配置
        if 'spx' in config:
            json_config["streamSettings"]["realitySettings"]["spiderX"] = config.get('spx', '/')

    return json_config



def generate_shadowsocks_config(ss_config, tag):
    json_config = {
        "tag": f"{tag}",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": ss_config["server"],
                    "method": ss_config["method"],
                    "password": ss_config["password"],
                    "port": ss_config["port"],
                    "uot": True
                }
            ]
        },
        "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {
          "header": {
            "type": "none"
          }
        },
        "sockopt": {
                "mark": 128,
                "tcpFastOpen": True
            },
      }
    }
    return json_config


def generate_trojan_config(trojan_json, tag):
    json_config = {
        "tag": f"{tag}",
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": trojan_json.get('server', ''),
                    "method": "chacha20",
                    "ota": False,  # Trojans does not use OTA by default
                    "password": trojan_json.get('password', ''),
                    "port": trojan_json.get(('port'), ''),
                    "level": 1  # Level can be set as needed
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "allowInsecure": False,  # You may adjust this based on your needs
                # 只在alpn存在且不为空字符串时保留alpn键
                **({"alpn": [trojan_json['alpn']]} if trojan_json.get('alpn') else {}),
                "fingerprint": "",  # You may set fingerprint if required
                "show": False
            },
            "sockopt": {
                "mark": 128,
                "tcpFastOpen": True
            },
        },
        "mux": {
            "enabled": False,
            "concurrency": -1
        }
    }
    return json_config


def generate_hysteria2_config(tag, filename=''):
    # 构建配置文件路径
    config_file_path = f"{HYSTERIA2_FOLDER}{filename}.json"
    config = load_xray_config(config_file_path)
    try:
        # 提取 socks5 字段
        socks5_data = config.get("socks5", {})
        # 提取 listen 字段的值
        listen_address = socks5_data.get("listen", "")

        # 从 listen 地址中提取端口号
        port = int(listen_address.split(":")[-1])
        server = '127.0.0.1'

        # hysteria2特殊配置
        json_config = {
            "tag": tag,
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": server,
                        "port": port,
                    }
                ]
            },
            "streamSettings": {
                "sockopt": {
                    "tcpFastOpen": True
                }
            }
        }
        return json_config
    except Exception as e:
        logging.error("hysteria2配置文件未生成无法解析端口连接")


"""
xray_node_outbound_add 函数
功能描述：

xray_node_outbound_add 函数用于向 Xray 配置文件中添加出站节点。函数接受三个参数：

proxy_url: 节点的代理 URL。
outbound_tag: 出站配置的标签。
config_path: Xray 配置文件的路径，默认为 CONFIG_PATH。
操作步骤：

读取现有的 Xray 配置。
判断指定标签的出站配置是否已存在，如果存在，给出警告并返回。
解码代理 URL，获取 Vmess 或 Socks 配置信息。
如果解码成功，生成出站节点配置并添加到 Xray 配置中。
调用 xray_node_route_add 函数添加路由规则。
调用 node_domain_set 函数为域名设置规则。
保存更新后的配置。
返回值：

如果成功，返回 1。
如果出现错误，返回相应的错误消息。
"""


def xray_node_outbound_add(proxy_url, outbound_tag, config_path=CONFIG_PATH):
    xray_config = load_xray_config(config_path)
    if not is_outbound_tag_exist(xray_config, outbound_tag):
        decode_data, protocol = decode_proxy_link(proxy_url)
        if decode_data:
            # 生成节点配置
            outbound = generate_node_outbound(decode_data, outbound_tag, protocol)
            xray_config["outbounds"].append(outbound)
            # 生成路由配置
            xray_node_route_add(xray_config, decode_data, protocol)
            node_domain_set(xray_config, decode_data)
            # 保存配置
            save_xray_config(xray_config, config_path)
            logging.info(f"✅已添加出站节点到配置文件，tag: {outbound_tag}")
            return 1
        else:
            logging.warning(INVALID_URL_MESSAGE)
            return 1
    else:
        logging.warning(f"{EXISTING_OUTBOUND_MESSAGE}，tag: {outbound_tag}")
        return 1


"""
decode_proxy_link 函数
功能描述：

decode_proxy_link 函数用于根据代理 URL 的协议类型解码配置信息。函数接受一个参数：

proxy_url: 代理 URL。
操作步骤：

如果 URL 包含 "vmess"，调用 decode_vmess_link 函数解码 Vmess 配置。
如果 URL 包含 "socks"，调用 decode_socks_link 函数解码 Socks 配置。
如果不属于以上两种协议，给出警告并返回 None。
返回值：

如果解码成功，返回相应的配置信息字典。
如果解码失败，返回 None。
"""


def decode_proxy_link(proxy_url):
    try:
        if "vmess://" in proxy_url.lower():
            return decode_vmess_link(proxy_url), "vmess"
        elif "vless://" in proxy_url.lower():
            return decode_vless_link(proxy_url), "vless"
        elif "socks://" in proxy_url.lower():
            return decode_socks_link(proxy_url), "socks"
        elif "trojan://" in proxy_url.lower():
            return decode_trojan_link(proxy_url), "trojan"
        elif "ss://" in proxy_url.lower():
            return decode_shadowsocks_link(proxy_url), "shadowsocks"
        elif "hysteria2://" in proxy_url.lower():
            return decode_hysteria2_url(proxy_url), "hysteria2"
        else:
            logging.warning("不支持的协议")
            return None,None
    except Exception as e:
        logging.error(f"解码连接时发生错误: {e}")
        return None,None


"""
xray_node_route_add 函数
功能描述：

xray_node_route_add 函数用于向 Xray 配置文件中添加节点路由规则。函数接受两个参数：

xray_config: 包含 Xray 配置的字典。
access_ip: 要添加到路由规则的 IP 地址或域名。
操作步骤：

提取 Xray 配置文件中位置 0 的规则（针对 IP 地址）和位置 1 的规则（针对域名）。
判断 access_ip 是 IP 地址还是域名。
根据类型选择要添加的规则和规则类型。
如果规则已存在，直接将新的 IP 地址或域名添加到原有规则中。
如果规则不存在，创建新的规则，并将其插入到相应的位置。
返回值：

无论操作成功或失败，都没有返回值。


"""


def xray_node_route_add(xray_config, decode_data, protocol):
    # vmess协议
    if protocol == 'vmess':
        access_ip = decode_data.get('add')
        port = decode_data.get('port')

    # socks协议
    elif protocol == 'socks':
        access_ip = decode_data.get('target_ip')
        port = decode_data.get('target_port')

    # shadowsocks协议
    elif protocol == 'shadowsocks':
        access_ip = decode_data.get('server')
        port = decode_data.get('port')

    # vless协议
    elif protocol == 'vless':
        access_ip = decode_data.get('ip')
        port = decode_data.get('port')

    # trojan,shadowsocks协议
    elif protocol == 'trojan':
        access_ip = decode_data.get('server')
        port = decode_data.get('port')

    # hy2协议特殊无需路由
    elif protocol == 'hysteria2':
        logging.info("hysteria2 xray路由添加跳过")
        return

    # 获取已有的规则列表
    existing_rules = xray_config["routing"].get("rules", [])

    # 检查该 IP、域名和端口是否已存在于任何规则中
    existing_rule = next((rule for rule in existing_rules if
                          (access_ip in rule.get("domain", []) and int(port) == int(rule.get("port", 0))) or
                          (access_ip in rule.get("ip", []) and int(port) == int(rule.get("port", 0)))), None)

    if access_ip == "127.0.0.1":
        logging.info(f"✅跳过 127.0.0.1 的路由规则: {access_ip}:{port}")
    else:
        if not existing_rule:
            # 判断 access_ip 是域名还是IP地址
            if is_ip_address(access_ip):
                new_rule = {"type": "field", "outboundTag": "direct", "ip": [access_ip], "port": port}
            else:
                new_rule = {"type": "field", "outboundTag": "direct", "domain": [access_ip], "port": port}

            xray_config["routing"].setdefault("rules", []).insert(0, new_rule)
        else:
            logging.warning(f"当前节点路由规则已经存在: {access_ip}:{port}")

    # if not existing_rule:
    #     # 判断 access_ip 是域名还是IP地址
    #     if is_ip_address(access_ip):
    #         new_rule = {"type": "field", "outboundTag": "direct", "ip": [access_ip], "port": port}
    #     else:
    #         new_rule = {"type": "field", "outboundTag": "direct", "domain": [access_ip], "port": port}
    #
    #     xray_config["routing"].setdefault("rules", []).insert(0, new_rule)
    # else:
    #     logging.warning(f"当前节点路由规则已经存在:{access_ip}:{port}")


"""
xray_node_outbound_remove 函数
功能描述：

xray_node_outbound_remove 函数用于从 Xray 配置文件中移除指定标签的出站配置。函数接受三个参数：

tag: 要移除的出站配置的标签。
hostname: （可选）如果是出站 DNS 配置，指定要移除的域名。
config_path: Xray 配置文件的路径，默认为 CONFIG_PATH。
操作步骤：

读取现有的 Xray 配置。
移除配置文件中所有标签为 tag 的出站配置。
如果提供了 hostname，调用 node_domain_unset 函数移除对应的出站 DNS 配置。
保存更新后的配置。
返回值：

如果成功，返回 1。
如果出现错误，返回字符串 "Xray Error"。
"""


def xray_node_outbound_remove(tag, hostname='', config_path=CONFIG_PATH):
    # 读取现有配置
    xray_config = load_xray_config(config_path)

    if xray_config is None:
        return "Xray Error"

    # 移除出站配置
    xray_config["outbounds"] = [outbound for outbound in xray_config.get("outbounds", []) if outbound.get("tag") != tag]

    # 移除出站DNS配置
    if hostname:
        node_domain_unset(hostname, xray_config)

    # 保存更新后的配置
    if save_xray_config(xray_config, config_path):
        logging.info(f"✅已成功移除节点outboundTag配置，tag: {tag}")
        return 1
    else:
        return "Xray Error"


"""
xray_node_route_remove 函数
功能描述：

xray_node_route_remove 函数用于从 Xray 配置文件中移除节点自己出站的路由规则。函数接受两个参数：

proxy_url: 节点的代理 URL。
config_path: Xray 配置文件的路径，默认为 CONFIG_PATH。
操作步骤：

解码代理 URL，获取节点的 IP 地址。
读取现有的 Xray 配置。
判断 IP 地址是 IPv4 还是 IPv6，寻找规则中包含该 IP 的规则，并移除对应的 IP。
如果是域名，寻找规则中包含该域名的规则，并移除对应的域名。
保存更新后的配置。
返回值：

如果成功，返回 1。
如果出现错误，返回字符串 "Xray Error"。

"""

def xray_node_route_remove(proxy_url, config_path=CONFIG_PATH):
    decode_data, protocol = decode_proxy_link(proxy_url)

    # 根据协议获取 IP 和端口
    if protocol == "socks":
        access_ip = decode_data.get("target_ip")
        port = decode_data.get("target_port")

    elif protocol == "vmess":
        access_ip = decode_data.get('add')
        port = decode_data.get('port')

    elif protocol == "vless":
        access_ip = decode_data.get('ip')
        port = decode_data.get('port')

    elif protocol == "trojan":
        access_ip = decode_data.get("server")
        port = decode_data.get("port")

    elif protocol == "shadowsocks":
        access_ip = decode_data.get("server")
        port = decode_data.get("port")

    else:
        def extract_socks5_port(decode_data):
            directory = "/etc/hysteria2"
            target_server = decode_data.get("server")
            if not target_server:
                return None

            for filename in os.listdir(directory):
                if filename.endswith(".json"):
                    filepath = os.path.join(directory, filename)
                    with open(filepath, "r") as file:
                        data = json.load(file)
                        if data.get("server") == target_server:
                            socks5_listen = data.get("socks5", {}).get("listen")
                            if socks5_listen:
                                _, port = socks5_listen.split(":")
                                return int(port)
            return None

        access_ip = '127.0.0.1'
        port = extract_socks5_port(decode_data)

    # 转换端口为整数类型
    try:
        port = int(port)
    except Exception:
        logging.error(f"端口转换失败：{port}")
        return

    logging.info(f"✅[ROUTE REMOVE] 协议: {protocol}, IP: {access_ip}, PORT: {port}")

    # 读取 Xray 配置
    xray_config = load_xray_config(config_path)
    rules = xray_config.get("routing", {}).get("rules", [])

    def ip_match(ip, rule_ips):
        for item in rule_ips:
            try:
                if '/' in item:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(item, strict=False):
                        return True
                elif ip == item:
                    return True
            except Exception:
                continue
        return False

    new_rules = []
    for rule in rules:
        matched = False
        rule_ips = rule.get("ip", [])
        rule_port = rule.get("port")

        ip_matched = ip_match(access_ip, rule_ips)
        port_matched = (rule_port == port)

        # Debug 输出
        logging.debug(f"[检查规则] IPs: {rule_ips}, Port: {rule_port} => IP匹配: {ip_matched}, 端口匹配: {port_matched}")

        if ip_matched and port_matched:
            rule['ip'] = [ip for ip in rule_ips if ip != access_ip]
            if not rule['ip']:
                logging.info(f"✅已清除规则: {rule}")
                continue  # 整个规则 IP 为空时不保留
            else:
                logging.info(f"✅更新规则，移除 IP：{access_ip}")
                new_rules.append(rule)
        else:
            new_rules.append(rule)

    # 更新配置
    xray_config["routing"]["rules"] = new_rules

    # 保存配置
    if save_xray_config(xray_config, config_path):
        logging.info(f"✅✅ 成功移除节点出站规则: {protocol}://{access_ip}:{port}")
    else:
        logging.error("❌ Xray 配置保存失败")

'''
 get_device_addresses 函数的功能描述如下：

get_device_addresses 函数用于解析原始文本并验证设备IP地址。函数接受一个参数：

raw_text: 包含设备IP地址的原始文本。
函数执行以下操作：

尝试将原始文本中的IP地址提取出来，去掉空白字符，以逗号分隔，并生成一个IP地址列表。
调用 validate_device_addresses 函数验证IP地址的有效性。
如果验证出错，返回包含错误消息的元组 (None, error_message)。
如果验证成功，去掉列表中的重复IP地址，生成一个不含重复IP地址的列表，返回 (unique_ip_addresses, None)。
   
'''


def get_device_addresses(raw_text):
    try:
        ip_addresses = [ip.strip() for ip in raw_text.replace('\n', ',').split(',') if ip.strip()]

        # 验证IP地址
        error_message = validate_device_addresses(ip_addresses)
        if error_message:
            logging.error(f"验证错误: {error_message}")
            return None

        # 去掉重复的IP地址
        unique_ip_addresses = list(set(ip_addresses))
        return unique_ip_addresses
    except Exception as e:
        logging.exception(f"关联设备IP地址时发生错误: {str(e)}")
        return None, f"关联设备IP地址时发生错误: {str(e)}"


"""
validate_device_addresses 函数的功能描述如下：

validate_device_addresses 函数用于验证设备IP地址的有效性。函数接受一个参数：

ip_addresses: 包含设备IP地址的列表。
函数执行以下操作：

对于每个IP地址，尝试创建一个 ipaddress.ip_network 对象，如果失败则抛出 ValueError。
如果创建成功，记录验证成功的日志信息。
如果创建失败，记录验证失败的日志信息，返回包含错误消息的字符串 f'无效的IP地址: {ip}'。
最终，get_device_addresses 函数返回一个元组 (ip_addresses, error_message)，其中 ip_addresses 为去重后的设备IP地址列表，error_message 为验证出错时的错误消息。

"""


def validate_device_addresses(ip_addresses):
    try:
        for ip in ip_addresses:
            try:
                ip_network = ipaddress.ip_network(ip, strict=False)
                # 记录成功的验证
                logging.info(f'有效的IP地址: {ip}')
            except ValueError:
                logging.error(f'无效的IP地址: {ip}')
                return f'无效的IP地址: {ip}'
        return None
    except Exception as e:
        logging.exception(f"验证IP地址时发生错误: {str(e)}")
        return f"验证IP地址时发生错误: {str(e)}"


"""
generate_device_route(ip_string, tag): 该函数用于生成设备路由配置，接受两个参数：

ip_string: 一个包含一个或多个IP地址的字符串，用逗号分隔。
tag: 出站标签，用于识别设备的出站配置。
函数根据 ip_string 是否存在来确定执行不同的操作：

如果 ip_string 存在，将其分割成IP地址列表，并生成一个路由配置字典，包含源IP地址列表和出站标签。
如果 ip_string 不存在，调用 xray_route_remove 函数清除与给定标签和匹配类型相关的路由出站规则。
返回生成的路由配置字典或 None。
"""


def generate_device_route(ip_string, tag):
    if ip_string:
        # 如果 ip_string 存在，将其分割成 IP 地址列表
        ip_list = [ip.strip() for ip in ip_string.split(',')]
        route_config = {
            "type": "field",
            "source": ip_list,
            "outboundTag": f"{tag}",
        }
    else:
        # 如果 ip_string 不存在，则清除 IP 地址路由出站规则
        xray_route_remove(tag, "source")
        return None

    return route_config


"""
xray_route_rule(route_dict, match_type, config_path=CONFIG_PATH): 该函数用于添加或更新Xray的路由规则，接受三个参数：

route_dict: 包含路由规则信息的字典。
match_type: 匹配类型，例如"source"。
config_path: Xray配置文件路径，默认为全局变量 CONFIG_PATH。
函数执行以下操作：

读取现有的Xray配置。
检查是否已存在相同的源和出站标签组合的规则，如果存在则更新规则，否则添加新的路由规则。
保存更新后的配置文件。
如果保存成功，返回1，否则返回 "Xray 错误"。
"""


def xray_route_rule(route_dict, match_type, config_path=CONFIG_PATH):
    # 读取现有配置
    xray_config = load_xray_config(config_path)
    outbound_tag = route_dict.get('outboundTag')

    # 根据 match_type 确定获取的键名
    target_key = match_type if match_type in ('ip', 'source') else 'ip'

    # 获取所有的键值
    selected_target_ips = route_dict.get(target_key, [])

    # 检查是否已存在相同的 type、match_type 和 outboundTag 组合
    existing_rules = xray_config.get('routing', {}).get('rules', [])

    for existing_rule in existing_rules:
        if (
            existing_rule.get('type') == 'field'
            and existing_rule.get(match_type)
            and existing_rule.get('outboundTag') == outbound_tag
        ):
            # 更新规则
            existing_rule.update(route_dict)
            logging.info(f"✅更新源为：{existing_rule.get(match_type)}，出站标签为：{outbound_tag} 的规则")
            break
    else:
        # 如果不存在则添加新的路由规则
        routing_rules = xray_config.setdefault('routing', {}).setdefault('rules', [])
        routing_rules.insert(-2, route_dict)
        logging.info(f"✅添加新规则，源为：{route_dict.get(match_type)}，出站标签为：{outbound_tag}。操作成功。")

    # 复制现有规则以进行安全迭代
    for existing_rule in existing_rules.copy():
        # 移除相同的IP值，但是出站标签不等于当前出站标签的情况下
        for address in selected_target_ips:
            if existing_rule.get('outboundTag') != outbound_tag and address in existing_rule.get(match_type, []):
                existing_rule[match_type].remove(address)
                # 如果 match_type 对应的值为空了，则移除整个规则
                if not existing_rule.get(match_type):
                    existing_rules.remove(existing_rule)
                logging.info(f"✅已移除源为：{address}，出站标签为：{outbound_tag} 的规则")

    # 保存更新后的配置
    if save_xray_config(xray_config, config_path):
        return 1
    else:
        return "Xray 错误"



"""
xray_route_remove(tag, match_type, config_path=CONFIG_PATH): 该函数用于删除与给定标签和匹配类型相关的Xray路由规则，接受三个参数：

tag: 出站标签，用于识别设备的出站配置。
match_type: 匹配类型，例如"source"。
config_path: Xray配置文件路径，默认为全局变量 CONFIG_PATH。
函数执行以下操作：

读取现有的Xray配置。
删除使用给定出站标签的路由规则。
保存更新后的配置文件。
如果保存成功，记录相关信息并返回 None，否则记录错误信息并返回 "Xray 错误"。

"""


def xray_route_remove(tag, match_type, config_path=CONFIG_PATH):
    # 读取现有配置
    xray_config = load_xray_config(config_path)

    # 删除使用这个出站的路由规则
    routing_rules = xray_config.get('routing', {}).get('rules', [])
    updated_routing_rules = [rule for rule in routing_rules if
                             not (rule.get('outboundTag') == tag and match_type in rule)]

    xray_config['routing']['rules'] = updated_routing_rules

    # 保存更新后的配置
    if save_xray_config(xray_config, config_path):
        logging.info(f"✅已移除出站节点关联设备ROUTE规则，tag: {tag}, 条件: {match_type}")
    else:
        logging.error("Xray 错误")
        return "Xray Error"


"""
xray_device_route_handler 函数用于处理设备路由配置的更新，接受两个参数：

proxys: 代理设备对象，包含设备的相关信息，如 device_ip 和 tag。
raw_text: 包含设备IP地址的原始文本。

函数执行以下操作：

调用 get_device_addresses 函数，解析原始文本获取设备的IP地址列表和错误消息。
如果解析出错，返回包含错误消息的字典 { 'success': False, 'message': error_message }。
如果解析成功，将设备的IP地址更新到数据库中。
重新获取数据库中最新的 device_ip 和 tag 值。
使用 generate_device_route 函数生成和更新设备的路由配置。
如果生成成功，使用 xray_route_rule 函数添加新的路由规则，并记录成功的日志信息。
如果生成失败，记录错误的日志信息。
最终，函数返回包含成功标志和消息的字典 { 'success': True, 'message': 'IP地址更新成功' } 或 { 'success': False, 'message': 'IP地址更新失败' }。

"""


def xray_device_route_handler(proxys, raw_text):
    ip_addresses = get_device_addresses(raw_text)

    # 查询数据库中所有的记录,下面的功能主要解决添加IP被其它的代理绑定，这样可以清理掉数据库中已经存在于别的代理的设备IP
    all_proxy_records = ProxyDevice.query.all()

    # 遍历所有记录
    for proxy in all_proxy_records:
        # 如果记录的device_ip字段不为空，则进行处理
        if proxy.device_ip:
            # 将记录的device_ip字段中的值按逗号分隔为列表
            device_ips = proxy.device_ip.split(',')
            # 移除匹配到的IP地址
            updated_ips = [ip for ip in device_ips if ip not in ip_addresses]
            # 更新device_ip字段为移除匹配到的IP地址后的值
            proxy.device_ip = ','.join(updated_ips) if updated_ips else None

    # 提交更改到数据库
    db.session.commit()

    # 更新数据库
    proxys.device_ip = ','.join(ip_addresses) or None
    db.session.commit()

    # 重新获取数据库中最新的 device_ip 和 tag 值
    device_ip = proxys.device_ip
    tag = proxys.tag
    protocol = proxys.protocol
    route_dict = generate_device_route(device_ip, tag)

    if route_dict:
        xray_route_rule(route_dict, "source")

        logging.info(f"✅添加设备路由规则成功：{device_ip}-出站路由：{tag}")
    else:
        logging.error(f"添加设备路由规则失败：{device_ip}-出站路由：{tag}")

    return {'success': True, 'message': 'IP地址更新成功'}

def excel_import_device_route_handler():
    # 打开 JSON 文件并加载数据
    xray_config = load_xray_config(CONFIG_PATH)
    rules = xray_config.get('routing', {}).get('rules', [])

    # 过滤出同时满足条件的规则并移除
    filtered_rules = [rule for rule in rules if rule.get('type') == 'field' and 'source' in rule]
    for rule in filtered_rules:
        rules.remove(rule)

    # 更新出站绑定设备IP规则
    xray_config['routing']['rules'] = rules
    save_xray_config(xray_config,CONFIG_PATH)

    # 查询条件：device_ip 不为空的记录
    proxies_with_ip = ProxyDevice.query.filter(ProxyDevice.device_ip != None).all()
    # 循环执行函数
    for proxy in proxies_with_ip:
        device_ip = proxy.device_ip
        tag = proxy.tag
        route_dict = generate_device_route(device_ip, tag)
        if route_dict:
            xray_route_rule(route_dict, "source")
            logging.info(f"✅EXCEL导入设备关联代理成功：{device_ip}-出站路由：{tag}")
        else:
            logging.error(f"EXCEL导入设备关联代理失败：{device_ip}-出站路由：{tag}")


"""

xray_proxies_info_handler 函数
功能描述：

xray_proxies_info_handler 函数用于处理代理URL的信息。该函数执行以下操作：

从 xray 配置中删除出站配置。
将新的出站配置添加到 xray 配置中。
重启 Xray 服务。
使用带有重试机制的函数获取代理的 IP 信息，最多尝试 5 次。
如果成功获取代理信息，则更新数据库中相应的记录；否则，更新数据库字段 status 为 'fail'。
操作步骤：

调用公用函数 xray_node_outbound_remove，从 xray 配置中删除出站配置，配置文件路径为 CHECK_PATH。
调用公用函数 xray_node_outbound_add，将新的出站配置添加到 xray 配置中，使用给定的 proxy_url 和标签 'proxy'，配置文件路径为 CHECK_PATH。
调用公用函数 restart_xray_service，重启 Xray 服务，服务名称为 'xray-check'。
使用带有重试机制的函数 curl_proxies_info 获取代理的 IP 信息，最多尝试 5 次，每次等待 1 秒。
检查 result 的值，如果等于 1，则表示成功获取代理信息，不执行后续步骤；否则，执行以下步骤。
调用公用函数 update_proxies_fail，更新数据库字段 status 为 'fail'，使用给定的 proxy_url。
注意： 该函数涉及到 Xray 配置的修改、服务重启以及对代理信息的获取和数据库更新。在执行此函数之前，请确保已经备份相关的配置文件和数据库，以防意外情况。
"""


def generate_test_config(protocol, proxy_url, tag, port):
    inbound = {
        "tag": f"{tag}",
        "port": port,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
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
        "sniffing": {
            "enabled": True,
            "destOverride": [
                "http",
                "tls"
            ]
        }
    }

    routing = {
        "type": "field",
        "inboundTag": f"{tag}",
        "outboundTag": f"{tag}",
    }

    decode_data, protocol = decode_proxy_link(proxy_url)
    if decode_data:
        # 生成节点配置
        if protocol == 'hysteria2':

            hysteria2_filename = ProxyDevice.query.filter_by(proxy_url=proxy_url).first().tag
            # hysteria2 节点TAG做文件名参数
            outbound = generate_hysteria2_config(tag, hysteria2_filename)

        else:
            outbound = generate_node_outbound(decode_data, tag, protocol)

        logging.info(f"✅生成的 Outbound 配置: {outbound}")
    else:
        logging.error("无法生成 Outbound 配置.")

    return inbound, outbound, routing


def multi_process_test(result):
    process = []
    for id, port in result.items():
        # 并发多线程实现快速检测服务
        t = Thread(target=port_test, args=(id, port,))
        t.start()
        process.append(t)

        if len(result) <= 1:
            while True:
                if t.is_alive():
                    time.sleep(5)
                else:
                    break
        else:
            time.sleep(0.1)
            continue

    # 阻塞线程，等待执行完毕在返回
    for thread in process:
        thread.join()

    return test_result


def port_test(proxies_id, port):
    test1 = "curl -s --connect-timeout 3 -m 3 -x socks5h://127.0.0.1:{0} ipinfo.io".format(port)
    test2 = "curl -s --connect-timeout 3 -m 3 -x socks5h://127.0.0.1:{0} ip-api.com".format(port)
    test3 = "curl -s --connect-timeout 3 -m 3 -x socks5h://127.0.0.1:{0} ifconfig.me".format(port)
    test1_result = subprocess.getstatusoutput(test1)
    test2_result = subprocess.getstatusoutput(test2)
    test3_result = subprocess.getstatusoutput(test3)

    if test1_result[0] == 0:
        test_result[proxies_id] = test1_result[1]
        logging.info(f"✅代理ID{proxies_id} INFOIO测试结果: {test1_result[1]}")
    elif test2_result[0] == 0:
        test_result[proxies_id] = test2_result[1]
        logging.info(f"✅代理ID{proxies_id} IP-API测试结果: {test2_result[1]}")
    elif test3_result[0] == 0:
        test_result[proxies_id] = test3_result[1]
        logging.info(f"✅代理ID{proxies_id}IFCONFIG.ME测试结果: {test3_result[1]}")
    else:
        test_result[proxies_id] = "Inactive"


def xray_proxies_info_handler(selected_items):
    xray_config = {
        "inbounds": [],
        "outbounds": [],
        "routing": {
            "rules": []
        }
    }

    result = {}
    global test_result
    test_result.clear()
    # 存储已经生成的端口号
    used_ports = set()
    for proxies_id in selected_items:
        # tag = generate_tag()  #不生成TAG,直接使用现有库中的TAG值
        # 生成端口号并检查是否重复
        while True:
            port = random.randint(1024, 65534)
            if port not in used_ports and not is_local_port_in_use(port):
                used_ports.add(port)
                break
        proxies = ProxyDevice.query.filter_by(id=proxies_id).first()
        protocol = proxies.protocol
        proxies_url = proxies.proxy_url
        tag = proxies.tag
        # 添加代理条件ID和测试端口对应关系
        result[proxies_id] = port
        inbound, outbound, routing = generate_test_config(protocol, proxies_url, tag, port)

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
    for proxies_id, result in test_result.items():
        proxies = ProxyDevice.query.filter_by(id=proxies_id).first()
        if result == 'Inactive':
            proxies.status = 'Inactive'
        else:
            # 使用正则表达式去除 ANSI 转义序列
            result = re.sub(r'\x1b\[[0-9;]*m', '', result)
            # 尝试解析JSON结果
            try:
                ip_info = json.loads(result, strict=False)
                if ip_info.get('ip'):
                    proxies.node_ip = ip_info.get('ip', '')
                    proxies.country = ip_info.get('country', '')
                    proxies.status = 'Active'  # 更新status为'active'
                elif ip_info.get('query'):
                    proxies.node_ip = ip_info.get('query', '')
                    proxies.country = ip_info.get('country', '')
                    proxies.status = 'Active'  # 更新status为'active'
            except json.JSONDecodeError as e:
                proxies.node_ip = result
                proxies.status = 'Active'

        db.session.commit()

    # 执行关闭 xray-check 服务的命令
    os.system('sudo systemctl stop xray-check')

"""

xray_node_delete_handler 函数
功能描述：

xray_node_delete_handler 函数用于删除 Xray 节点和相关配置。该函数接收一个代理设备对象 proxy_device，并根据该对象包含的信息执行以下操作：

删除 Xray 出站配置和路由规则。
删除数据库中与代理设备相关的记录。
操作步骤：

从 proxy_device 对象中获取代理设备的相关信息，包括 proxy_url、tag 和 access_ip。
根据 access_ip 是否为 IP 地址，调用 xray_node_outbound_remove 函数删除对应的 Xray 出站配置。如果 access_ip 不是 IP 地址，则传递 hostname 参数。
调用 xray_route_remove 函数删除与设备相关的 Xray 路由规则。首先删除基于源 IP ("source") 的规则，然后删除基于目标 IP ("ip") 的规则。
调用 xray_node_route_remove 函数删除与代理设备相关的 Xray 节点路由规则。
在数据库中删除 proxy_device 记录，并提交更改。
注意： 该函数执行了一系列操作，包括删除配置文件中的规则和在数据库中删除记录。在执行此操作之前，请确保已经备份相关的配置文件和数据库，以防意外情况。

"""


def xray_node_delete_handler(proxy_device):
    if proxy_device:
        proxy_url = proxy_device.proxy_url
        tag = proxy_device.tag
        access_ip = proxy_device.access_ip
        protocol = proxy_device.protocol
        device_ip = proxy_device.device_ip

        # 删除对应的 Xray 出站配置和路由规则
        if is_ip_address(access_ip):
            xray_node_outbound_remove(tag)
        else:
            xray_node_outbound_remove(tag, hostname=access_ip)

        xray_route_remove(tag, "source")
        xray_route_remove(tag, "ip")
        xray_node_route_remove(proxy_url)

        if protocol == 'hysteria2':
            uninstall_hysteria2_service(tag)

        # 删除数据库记录
        db.session.delete(proxy_device)
        db.session.commit()


"""

check_relay_rules 函数
功能描述：

check_relay_rules 函数用于验证中继规则的格式和有效性。该函数接收一个包含中继规则的字符串 rules，按行拆分规则，并逐一验证每条规则的格式。如果规则格式有效，将提取规则中的协议、源端口、目标 IP 
和目标端口，并将这些信息保存到一个字典中。最终，函数返回一个布尔值表示验证是否成功，以及一个包含验证通过的规则信息的列表。

操作步骤：

将传入的规则字符串按行拆分成列表 rules_list。
定义正则表达式模式 rule_pattern 用于匹配每条规则的格式。规则格式应为 "协议:源端口:目标IP:目标端口"，其中协议为 "tcp" 或 "udp"，端口为 1 到 65535 之间的整数，目标 IP 为有效的 IP 地址。
初始化一个空列表 validated_rules 用于存储验证通过的规则信息。
遍历 rules_list，逐一验证每条规则的格式。如果规则格式有效，提取协议、源端口、目标 IP 和目标端口，将这些信息保存到一个字典，并添加到 validated_rules 列表中。
如果规则格式无效，记录错误日志，并返回验证失败的信息。
如果所有规则验证通过，返回验证成功的布尔值和包含规则信息的列表。
注意： 该函数使用正则表达式进行规则格式的验证，确保规则符合指定的格式要求。如果规则格式无效，函数将返回验证失败的信息。

"""


def check_relay_rules(rules):
    rules_list = rules.splitlines()
    rule_pattern = re.compile(r'^(tcp|udp):(\d{1,5}):(\d+\.\d+\.\d+\.\d+):(\d{1,5})$')
    validated_rules = []

    # 逐一验证每条规则
    for rule in rules_list:
        cleaned_rule = rule.strip()  # 去掉每行前后的空白字符
        if not cleaned_rule:
            continue  # 跳过空行
        match = rule_pattern.match(cleaned_rule)

        if match:
            protocol = match.group(1)
            source_port = int(match.group(2))
            target_ip = match.group(3)
            target_port = int(match.group(4))

            if (protocol.lower() not in ['tcp', 'udp'] or
                    not (0 <= source_port <= 65535) or
                    not (0 <= target_port <= 65535) or
                    not is_ip_address(target_ip)):
                logging.error("规则 {} 的格式无效".format(rule))
                return False, "规则 {} 的格式无效".format(rule)
            else:
                validated_rules.append({
                    'protocol': protocol,
                    'source_port': source_port,
                    'target_ip': target_ip,
                    'target_port': target_port
                })
        else:
            logging.error("规则 {} 的格式无效".format(rule))
            return False, "规则 {} 的格式无效".format(rule)

    return True, validated_rules


"""
relay_info_savedb 函数
功能描述：

relay_info_savedb 函数用于保存中继规则信息到数据库。函数接收一个包含中继规则信息的列表 validated_rules，遍历列表中的每个规则，检查数据库中是否已存在相同的规则，如果不存在则将规则保存到数据库。

操作步骤：

对于传入的每个 rule_info，提取规则信息，包括协议 (protocol)、源端口 (source_port)、目标 IP (target_ip)、目标端口 (target_port)。
查询数据库，检查是否已存在相同的规则。如果存在，则记录警告日志，并跳过保存。
如果数据库中不存在相同的规则，创建一个新的 RelayConnection 对象，并将规则信息添加到对象中。
尝试将新创建的 RelayConnection 对象添加到数据库，并提交事务。
如果添加成功，记录成功的日志信息；如果添加失败，记录错误日志，并回滚事务。
注意： 在实际使用中，需要确保数据库操作的事务性，以防止数据不一致或错误。此外，应谨慎处理数据库连接和关闭，以确保数据库连接的及时释放。
"""


def relay_info_savedb(validated_rules):
    for rule_info in validated_rules:
        protocol = rule_info['protocol']
        source_port = rule_info['source_port']
        target_ip = rule_info['target_ip']
        target_port = rule_info['target_port']

        # 检查数据库中是否已存在相同的规则
        existing_rule = RelayConnection.query.filter_by(
            protocol=protocol,
            source_port=source_port,
            target_ip=target_ip,
            target_port=target_port
        ).first()

        if existing_rule:
            logging.warning(f"规则已存在，跳过保存: {rule_info}")
        else:
            try:
                new_connection = RelayConnection(
                    protocol=protocol,
                    source_port=source_port,
                    target_ip=target_ip,
                    target_port=target_port,
                )

                db.session.add(new_connection)
                db.session.commit()
                logging.info(f"✅成功保存中转规则到数据库: {rule_info}")
            except Exception as e:
                db.session.rollback()
                logging.error(f"保存中转规则到数据库时出错: {str(e)}")


"""
process_single_relay 函数
功能描述：

process_single_relay 函数用于处理单个中转连接规则的执行操作。该函数接收一个 relay_connection 对象和一个 exec_type 参数，执行的操作类型包括删除 (delete)、启动 (on)、和关闭 
(off)。

操作步骤：

根据传入的 exec_type 类型，执行相应的操作：
如果 exec_type 为 delete，则调用 socat_process_kill 函数终止 socat 进程，并从数据库中删除中继连接规则。
如果 exec_type 为 on，则调用 relay_connection_on 函数启动 socat 进程，并将中继连接规则的状态设置为 1。
如果 exec_type 为 off，则调用 socat_process_kill 函数终止 socat 进程，并将中继连接规则的状态设置为 0。
记录相应的日志信息，包括成功执行的中继连接信息。
注意： 该函数通过调用其他函数来完成具体的操作，执行时需要确保相关函数的正确性和可用性。在实际使用中，还需注意保护数据库操作的事务性。
"""


def process_single_relay(relay_connection, exec_type):
    try:
        if exec_type == 'delete':
            socat_process_kill(relay_connection)
            db.session.delete(relay_connection)
        elif exec_type == 'on':
            relay_connection_on(relay_connection)
            relay_connection.status = 1
        elif exec_type == 'off':
            socat_process_kill(relay_connection)
            relay_connection.status = 0

        db.session.commit()
        logging.info(
            f"执行中转 {relay_connection.target_ip}:{relay_connection.target_port}:，执行类型: {exec_type} 成功！")

    except Exception as e:
        logging.error(f"中转 {relay_connection.target_ip} 出错，执行类型 {exec_type}: {str(e)}")


"""
socat_process_kill 函数
功能描述：

socat_process_kill 函数用于终止中继连接规则的 socat 进程。该函数接收一个 relay_connection 对象作为参数，包含中继规则的源端口信息。

操作步骤：

从传入的 relay_connection 对象中获取源端口 (source_port)。
构造命令使用 ss、grep 和 awk 过滤出匹配的 socat 进程的 PID。
使用 subprocess.getstatusoutput 执行命令并获取输出，即 socat 进程的 PID。
如果成功获取 PID，则使用 subprocess.run 执行 kill 命令终止 socat 进程。
根据执行结果记录相应的日志信息。
注意： 该函数的目的是通过命令行查找和终止匹配的 socat 进程。在实际执行中，需要确保命令可用，并且可能需要根据系统环境的不同进行适当的调整。
"""


def socat_process_kill(relay_connection):
    # 获取中转规则信息
    source_port = relay_connection.source_port

    # 构造命令来获取匹配的 socat 进程
    ss_command = f"pkill -f LISTEN:{source_port}"

    # 使用 subprocess 执行命令并获取输出
    process_pid = subprocess.getstatusoutput(ss_command)[1]
    os.system(ss_command)
    if process_pid:
        # 杀死匹配的 socat 进程
        try:
            subprocess.run(f"kill {process_pid}", shell=True)
            logging.info(f"✅成功杀死 socat 进程，进程 ID： {process_pid}")

        except subprocess.CalledProcessError:
            logging.info(f"✅进程 {process_pid} 不存在，无需杀死")
    else:
        logging.info(f"✅无法获取 socat 进程的 PID，无法杀死进程")


"""
relay_connection_on 函数
功能描述：

relay_connection_on 函数用于启动中继连接规则。该函数接收一个 relay_connection 对象作为参数，包含中继规则的相关信息，例如源端口、目标 IP、目标端口和协议。

操作步骤：

从传入的 relay_connection 对象中获取源端口 (source_port)、目标 IP (target_ip)、目标端口 (target_port) 和协议 (protocol)。
根据协议使用 socat 动态构造启动命令。
使用 subprocess.run 启动 socat 进程，将标准错误输出 (stderr) 重定向到 /dev/null。
使用 socket 模块检查目标 IP 和端口是否打开。如果连接成功，记录成功启动 socat 进程的日志；否则，记录错误日志。
返回值：

该函数没有明确的返回值，但会根据执行结果记录相应的日志信息。

注意： 该函数的目的是启动 socat 进程以实现中继连接规则。在实际执行中，需要确保 socat 命令可用，并且可能需要根据系统环境的不同进行适当的调整。

"""


def relay_connection_on(relay_connection):
    source_port = relay_connection.source_port
    target_ip = relay_connection.target_ip
    target_port = relay_connection.target_port
    protocol = relay_connection.protocol.lower()

    if protocol == 'udp':
        cmd = [
            'socat',
            '-T', '30',
            '-d',
            f'UDP4-LISTEN:{source_port},reuseaddr,fork',
            f'UDP4:{target_ip}:{target_port}'
        ]
    else:
        cmd = [
            'socat',
            '-d',
            f'TCP4-LISTEN:{source_port},reuseaddr,fork',
            f'TCP4:{target_ip}:{target_port}'
        ]

    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

        if protocol == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.sendto(b'', (target_ip, target_port))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target_ip, target_port))

        logging.info(f"✅ 成功启动 socat 进程，中转规则：{' '.join(cmd)}")
    except subprocess.CalledProcessError:
        logging.error(f"❌ 启动 socat 进程失败，中转规则：{' '.join(cmd)}")
    except (socket.error, socket.timeout) as e:
        logging.error(f"❌ 端口未打开，中转规则：{' '.join(cmd)}，错误：{e}")


"""
relay_ip_route_set 函数
功能描述：

relay_ip_route_set 函数用于更新中转连接的 IP 路由规则。函数接受两个参数：

tag: 中继连接的标签。
selected_target_ips: 一个包含选定的目标 IP 地址的列表。
操作步骤：

使用 SQLAlchemy 查询语句，将具有指定标签的所有中继连接的 tag 字段更新为 None（清除标签）。
使用 SQLAlchemy 查询语句，将选定的目标 IP 地址的中继连接的 tag 字段更新为指定的标签。
提交对数据库的更改。
如果选定的目标 IP 地址列表不为空，则创建一个包含 IP 路由规则的字典，包括类型为 "field"，IP 列表和出站标签。
调用 xray_route_rule 函数，将更新后的规则应用到 Xray 配置中。
如果选定的目标 IP 地址列表为空，则调用 xray_route_remove 函数，清除 IP 地址路由出站规则。
返回值：

如果选定的目标 IP 地址列表为空，返回 None。
如果选定的目标 IP 地址列表不为空，返回 1，表示规则已成功更新。
注意： 该函数在处理数据库更新和 Xray 规则更新时使用 SQLAlchemy 进行操作，确保了对数据库和配置文件的同步更改。此外，根据具体情况，可以在更新数据库和规则的过程中记录日志，以进行调试和监控。
"""


def relay_ip_route_set(tag, selected_target_ips):
    RelayConnection.query.filter_by(tag=tag).update({RelayConnection.tag: None}, synchronize_session='fetch')
    # 更新数据库中选定的 IP 的 tag 字段为指定的 tag
    RelayConnection.query.filter(RelayConnection.target_ip.in_(selected_target_ips)).update(
        {RelayConnection.tag: tag}, synchronize_session='fetch')
    db.session.commit()

    if selected_target_ips:
        # 清除所有当前标签的目标 IP
        route_dict = {
            "type": "field",
            "ip": list(selected_target_ips),
            "outboundTag": f"{tag}",
        }

        xray_route_rule(route_dict, "ip")

    else:
        # 如果 ip_string 不存在，则清除 IP 地址路由出站规则
        xray_route_remove(tag, "ip")
        return None


def set_proxy_chain(get_tag, post_tag):
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        logging.error(f"配置读取失败: {e}")
        return

    found = False
    for i, outbound in enumerate(config.get("outbounds", [])):
        if outbound.get("tag") == get_tag:
            new_outbound = OrderedDict()
            for k, v in outbound.items():
                if k != "proxySettings":
                    new_outbound[k] = v
            new_outbound["proxySettings"] = {
                "tag": post_tag
            }
            config["outbounds"][i] = new_outbound
            found = True
            break

    if not found:
        logging.warning(f"未找到 tag 为 {get_tag} 的 outbound")
        return

    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
        logging.info(f"✅成功设置 proxySettings: {get_tag} -> {post_tag}")
    except Exception as e:
        logging.error(f"配置写入失败: {e}")


def clear_proxy_chain(tag):
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        logging.error(f"配置读取失败: {e}")
        return

    found = False
    for outbound in config.get("outbounds", []):
        if outbound.get("tag") == tag:
            if "proxySettings" in outbound:
                del outbound["proxySettings"]
                found = True
            break

    if not found:
        logging.warning(f"未找到 tag 为 {tag} 的 outbound，或未设置 proxySettings")
        return

    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
        logging.info(f"✅成功移除 {tag} 的 proxySettings")
    except Exception as e:
        logging.error(f"配置写入失败: {e}")