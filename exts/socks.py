import json
import logging
import subprocess
import os
import random
import exts.proxy  # 假设你已经有了 exts.proxy 模块

def create_socks_service(tag):
    # 创建系统服务
    service_file_content = f"""[Unit]
Description=Xray {tag} Service
After=network.target
Wants=network.target

[Service]
Type=simple
PIDFile=/run/{tag}.pid
ExecStart=/usr/local/xos/xray/xray -config /usr/local/xos/xray/{tag}.json
Restart=always
RestartSec=5
StartLimitInterval=0
RestartPreventExitStatus=25
[Install]
WantedBy=multi-user.target"""
    service_filepath = f"/etc/systemd/system/{tag}.service"

    with open(service_filepath, 'w') as f:
        f.write(service_file_content)
    # 重新载入服务
    subprocess.run(['systemctl', 'daemon-reload'])
    # 设置开机自启动
    subprocess.run(['systemctl', 'enable', f'{tag}.service'])
    # 启动服务
    subprocess.run(['systemctl', 'start', f'{tag}.service'])



def get_random_port():
    # 生成端口号并检查是否重复
    while True:
        random_port = random.randint(60000, 65534)
        if not exts.proxy.is_local_port_in_use(random_port):
            break
    return random_port

def socks_iptables_rules(lan_ip, tproxy_port, type):

    # 清理掉绑定IP被绑定到其它代理节点的规则
    ips = exts.proxy.get_device_addresses(lan_ip)
    for ip in ips:
        ports = extract_port_from_iptables(ip)
        if ports:
            for port in ports:
                cmd1 = "iptables -t mangle -D TP_PRE -s {0} -p tcp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
                    ip, port)
                cmd2 = "iptables -t mangle -D TP_PRE -s {0} -p udp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
                    ip, port)
                subprocess.run(cmd1, shell=True)
                subprocess.run(cmd2, shell=True)
        else:
            break

    # 清理掉绑定到自己端口上的旧规则
    mangle_ips = get_ip_addresses_by_port(tproxy_port)
    for ip in mangle_ips:
        if ip:
            cmd1 = "iptables -t mangle -D TP_PRE -s {0} -p tcp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
                ip, tproxy_port)
            cmd2 = "iptables -t mangle -D TP_PRE -s {0} -p udp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
                ip, tproxy_port)
            subprocess.run(cmd1, shell=True)
            subprocess.run(cmd2, shell=True)
        else:
            break


    if type == 'add':
        cmd1 = "iptables -t mangle -I TP_PRE 5 -s {0} -p tcp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
            lan_ip, tproxy_port)
        cmd2 = "iptables -t mangle -I TP_PRE 5 -s {0} -p udp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
            lan_ip, tproxy_port)
        subprocess.run(cmd1, shell=True)
        subprocess.run(cmd2, shell=True)

    elif type == 'del':
         cmd1 = "iptables -t mangle -D TP_PRE -s {0} -p tcp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
             lan_ip, tproxy_port)
         cmd2 = "iptables -t mangle -D TP_PRE -s {0} -p udp -m mark --mark 0x40/0xc0 -j TPROXY --on-port {1} --on-ip 127.0.0.1 --tproxy-mark 0x0/0x0".format(
             lan_ip, tproxy_port)

         subprocess.run(cmd1, shell=True)
         subprocess.run(cmd2, shell=True)

    else:
        logging.error("Invalid option")


def extract_port_from_iptables(ip_address):
    try:
        # 执行命令并捕获输出
        output_bytes = subprocess.check_output(
            f'iptables -vnL -t mangle | grep {ip_address} | awk \'{{print $8, $15}}\' | cut -d ":" -f 2',
            shell=True,
        )
        # 解码输出并返回提取的端口号列表
        output_text = output_bytes.decode('utf-8')
        return output_text.split()
    except subprocess.CalledProcessError:
        # 如果命令执行失败，则返回空列表
        return []

def get_ip_addresses_by_port(port):
    try:
        # 执行命令并捕获输出
        output_bytes = subprocess.check_output(
            f'iptables -vnL -t mangle | awk \'$15 ~ /:{port}$/ && /TPROXY/ {{print $8}}\'',
            shell=True,
        )
        # 解码输出并返回IP地址列表
        output_text = output_bytes.decode('utf-8')
        ip_addresses = output_text.split()
        return ip_addresses
    except subprocess.CalledProcessError:
        # 如果命令执行失败，则返回空列表
        return []
def socks_service_config(tag, proxy_url, device_ip):
    decoded_data = exts.proxy.decode_socks_link(proxy_url)
    config = exts.proxy.generate_socks_config(decoded_data, tag)
    random_port = get_random_port()
    xray_config_content = {
        "log": {
            "loglevel": "warning",
            "error": f"/var/log/xray/{tag}_error.log",
            "access": f"/var/log/xray/{tag}_access.log"
        },
        "inbounds": [
            {
                "tag": "all-in",
                "port": random_port,
                "protocol": "dokodemo-door",
                "settings": {
                    "network": "tcp,udp",
                    "followRedirect": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                },
                "streamSettings": {
                    "sockopt": {
                        "tproxy": "tproxy"
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
                        "geoip:cn",
                        "geoip:private"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "outboundTag": tag,
                    "port": "0-65535"
                }
            ]
        }
    }
    # 将新的 SOCKS 配置添加到 outbounds 键中
    xray_config_content["outbounds"].append(config)
    exts.proxy.save_xray_config(xray_config_content, f"/usr/local/xos/xray/{tag}.json")
    create_socks_service(tag)
    socks_iptables_rules(device_ip,random_port,"add")


def uninstall_socks_service(tag,device_ip):
    # 加载配置文件
    config_file_path = f"/usr/local/xos/xray/{tag}.json"

    # 检查配置文件是否存在
    if not os.path.exists(config_file_path):
        logging.error(f"SOCKS 服务配置文件:{config_file_path} 没有.")
        return
    # 从配置文件中提取端口
    config = exts.proxy.load_xray_config(config_file_path)
    port = int(config.get("inbounds", [{}])[0].get("port", 0))

    socks_iptables_rules(device_ip, port, "del")

    # 删除配置文件
    config_filepath = f"/usr/local/xos/xray/{tag}.json"
    subprocess.run(['rm', '-f', config_filepath])

    # 停止并删除服务
    subprocess.run(['systemctl', 'stop', f'{tag}.service'])
    subprocess.run(['systemctl', 'disable', f'{tag}.service'])
    subprocess.run(['rm', '-f', f"/etc/systemd/system/{tag}.service"])

