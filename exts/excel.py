import logging
from io import BytesIO
import pandas as pd
from flask import send_file
from app.models import *
from exts.proxy import excel_import_device_route_handler


def export_excel(table_name):
    # 根据传入的表名获取数据，这里假设根据不同的表名获取不同的数据
    if table_name == 'proxy_devices':
        proxies = db.session.query(ProxyDevice).all()
        data = {
            'id': [proxy.id for proxy in proxies],
            'proxy_url': [proxy.proxy_url for proxy in proxies],
            'access_ip': [proxy.access_ip for proxy in proxies],
            'node_ip': [proxy.node_ip for proxy in proxies],
            'country': [proxy.country for proxy in proxies],
            'protocol': [proxy.protocol for proxy in proxies],
            'status': [proxy.status for proxy in proxies],
            'device_ip': [proxy.device_ip for proxy in proxies],
            'tag': [getattr(proxy, 'tag', '') for proxy in proxies],  # 安全写法，兼容无 tag
            'flag': [proxy.flag for proxy in proxies],
            'note': [proxy.note for proxy in proxies],
            'gateway': [proxy.gateway for proxy in proxies]
        }

    elif table_name == 'relay_connections':
        relay_connections = db.session.query(RelayConnection).all()
        data = {
            'id': [relay.id for relay in relay_connections],
            'protocol': [relay.protocol for relay in relay_connections],
            'source_port': [relay.source_port for relay in relay_connections],
            'target_ip': [relay.target_ip for relay in relay_connections],
            'target_port': [relay.target_port for relay in relay_connections],
            'alive': [relay.alive for relay in relay_connections],
            'info': [relay.info for relay in relay_connections],
            'status': [relay.status for relay in relay_connections],
            'note': [relay.note for relay in relay_connections]
        }

    elif table_name == 'conversion':
        convers = Conver.query.all()
        data = {
            'id': [conv.id for conv in convers],
            'proxy_ip': [conv.proxy_ip for conv in convers],
            'real_ip': [conv.real_ip for conv in convers],
            'country': [conv.country for conv in convers],
            'city': [conv.city for conv in convers],
            'inbound_protocol': [conv.inbound_protocol for conv in convers],
            'inbound_connections': [conv.inbound_connections for conv in convers],
            'outbound_protocol': [conv.outbound_protocol for conv in convers],
            'outbound_connections': [conv.outbound_connections for conv in convers],
            'tag': [getattr(conv, 'tag', '') for conv in convers],  # 安全写法
            'status': [conv.status for conv in convers],
            'flag': [conv.flag for conv in convers]
        }

    elif table_name == 'host':
        hosts = Host.query.all()
        data = {
            'id': [host.id for host in hosts],
            'user': [host.user for host in hosts],
            'country': [host.country for host in hosts],
            'day': [host.day for host in hosts],
            'ip': [host.ip for host in hosts],
            'account': [host.account for host in hosts],
            'password': [host.password for host in hosts],
            'port': [host.port for host in hosts],
            'website': [host.website for host in hosts],
            'remark': [host.remark for host in hosts],
            'active': [host.active for host in hosts]
        }

    else:
        return 'Invalid table name'

    # 创建 DataFrame
    df = pd.DataFrame(data)

    # 创建 Excel 文件
    excel_data = BytesIO()
    with pd.ExcelWriter(excel_data, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)

    excel_data.seek(0)

    # 返回 Excel 文件
    return send_file(excel_data, download_name=f'{table_name}.xlsx', as_attachment=True)


def import_excel(uploaded_file, table_name):
    try:
        df = pd.read_excel(uploaded_file, engine='openpyxl', dtype=str)
        df = df.dropna(how='all')  # 删除空行
    except Exception as e:
        logging.error(f'读取Excel文件时出错: {e}')
        return

    # 清空对应表数据
    if table_name == 'proxy_devices':
        ProxyDevice.query.delete()
    elif table_name == 'relay_connections':
        RelayConnection.query.delete()
    elif table_name == 'host':
        Host.query.delete()
    elif table_name == 'conversion':
        Conver.query.delete()
    else:
        logging.error(f"未知表名: {table_name}")
        return

    records = []

    for index, row in df.iterrows():
        try:
            if table_name == 'proxy_devices':
                record = ProxyDevice(
                    proxy_url=row['proxy_url'],
                    access_ip=row['access_ip'],
                    node_ip=row['node_ip'],
                    country=row['country'],
                    protocol=row['protocol'],
                    status=row['status'],
                    device_ip=row['device_ip'],
                    tag=row.get('tag', ''),
                    flag=row.get('flag', ''),
                    note=row.get('note', ''),
                    gateway=row.get('gateway', '')
                )

            elif table_name == 'relay_connections':
                record = RelayConnection(
                    protocol=row['protocol'],
                    source_port=int(row['source_port']),
                    target_ip=row['target_ip'],
                    target_port=int(row['target_port']),
                    alive=int(row['alive']) if 'alive' in row and pd.notna(row['alive']) else None,
                    info=row.get('info', ''),
                    status=row.get('status', ''),
                    note=row.get('note', '')
                )

            elif table_name == 'host':
                date_value = pd.to_datetime(row['day']).date() if 'day' in row and pd.notna(row['day']) else None
                record = Host(
                    user=row['user'],
                    country=row['country'],
                    day=date_value,
                    ip=row['ip'],
                    account=row['account'],
                    password=row['password'],
                    port=row['port'],
                    website=row['website'],
                    remark=row.get('remark', ''),
                    active=row.get('active', '')
                )

            elif table_name == 'conversion':
                record = Conver(
                    proxy_ip=row['proxy_ip'],
                    real_ip=row['real_ip'],
                    country=row['country'],
                    city=row['city'],
                    inbound_protocol=row['inbound_protocol'],
                    inbound_connections=row['inbound_connections'],
                    outbound_protocol=row['outbound_protocol'],
                    outbound_connections=row['outbound_connections'],
                    tag=row.get('tag', ''),
                    status=row.get('status', ''),
                    flag=row.get('flag', '')
                )

            records.append(record)

        except KeyError as e:
            logging.error(f"Excel 行缺少必要字段 {e}，跳过该行: {row.to_dict()}")
        except ValueError as e:
            logging.error(f"Excel 行类型错误 {e}，跳过该行: {row.to_dict()}")

    # 批量保存
    try:
        if records:
            db.session.bulk_save_objects(records)
            db.session.commit()
            if table_name == 'proxy_devices':
                excel_import_device_route_handler()
            logging.info(f"导入 {table_name} 数据表成功，共 {len(records)} 条记录")
        else:
            logging.warning(f"{table_name} 表无有效记录可导入")
    except Exception as e:
        db.session.rollback()
        logging.error(f"导入 {table_name} 数据表失败: {e}")
