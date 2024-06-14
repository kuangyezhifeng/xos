# 配置参数
from app.models import *
from exts.proxy import save_xray_config
import os
import subprocess
import time

CONFIG_DIR = "/usr/local/xos/xray"
XRAY_EXEC = "/usr/local/xos/xray/xray"

def alone_proxy_url(ip_address):
    device = ProxyDevice.query.filter(ProxyDevice.device_ip.contains(ip_address)).first()
    if device:
        return device.proxy_url
    return None


def alone_socks_config(proxy_port, socks_ip, socks_port, socks_user, socks_pass):
    config = {
        "inbounds": [
            {
                "tag": str(proxy_port),
                "port": proxy_port,
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
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "AsIs"
                }
            },
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {
                    "address": "8.8.8.8"
                }
            },
            {
                "tag": "socks",
                "protocol": "socks",
                "settings": {
                    "servers": [
                        {
                            "address": socks_ip,
                            "port": int(socks_port),
                            "users": [
                                {
                                    "user": socks_user,
                                    "pass": socks_pass
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "sockopt": {
                        "tcpFastOpen": True
                    }
                }
            }
        ],
        "dns": {
            "hosts": {
                "dns.google": ["8.8.8.8", "8.8.4.4"]
            },
            "servers": ["8.8.8.8", "1.1.1.1"]
        },
        "routing": {
            "domainStrategy": "IPOnDemand",
            "domainMatcher": "mph",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["all-in"],
                    "port": 53,
                    "outboundTag": "dns-out"
                },
                {
                    "type": "field",
                    "inboundTag": [str(proxy_port)],
                    "outboundTag": "socks"
                }
            ]
        }
    }
    return config


def alone_noauth_socks_config(proxy_port, socks_ip, socks_port):
    config = {
        "inbounds": [
            {
                "tag": str(proxy_port),
                "port": proxy_port,
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
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "AsIs"
                }
            },
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {
                    "address": "8.8.8.8"
                }
            },
            {
                "tag": "socks",
                "protocol": "socks",
                "settings": {
                    "servers": [
                        {
                            "address": socks_ip,
                            "port": int(socks_port)
                        }
                    ]
                },
                "streamSettings": {
                    "sockopt": {
                        "tcpFastOpen": True
                    }
                }
            }
        ],
        "dns": {
            "hosts": {
                "dns.google": ["8.8.8.8", "8.8.4.4"]
            },
            "servers": ["8.8.8.8", "1.1.1.1"]
        },
        "routing": {
            "domainStrategy": "IPOnDemand",
            "domainMatcher": "mph",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["all-in"],
                    "port": 53,
                    "outboundTag": "dns-out"
                },
                {
                    "type": "field",
                    "inboundTag": [str(proxy_port)],
                    "outboundTag": "socks"
                }
            ]
        }
    }
    return config


def check_port(port):
    result = subprocess.run(["ss", "-ntl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return str(port) in result.stdout

def alone_running_socks(proxy_port, config):
    config_path = os.path.join(CONFIG_DIR, f"{proxy_port}.json")
    save_xray_config(config, config_path)

    max_attempts = 3
    for attempt in range(max_attempts):
        # 尝试杀死现有进程
        subprocess.Popen(["pkill", "-f", str(proxy_port) + ".json"])
        time.sleep(1)  # 等待进程被杀死

        # 检查端口是否已关闭
        if not check_port(proxy_port):
            # 重新启动进程
            subprocess.Popen(["nohup", XRAY_EXEC, "-c", config_path, "&"])
            time.sleep(1)  # 等待进程启动

            # 检查端口是否已打开
            if check_port(proxy_port):
                return True
    return False



