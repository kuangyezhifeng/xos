# 配置参数
from app.models import *


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

