import logging
from io import BytesIO
import pandas as pd
from flask import send_file
from app.models import *
from exts.proxy import excel_import_device_route_handler
def export_excel(table_name):
    # 根据传入的表名获取数据，这里假设根据不同的表名获取不同的数据
    if table_name == 'proxy_devices':
        # 获取数据
        proxies = db.session.query(ProxyDevice).all()
        # 创建 DataFrame 对象
        data = {
            'id': [proxy.id for proxy in proxies],
            'proxy_url': [proxy.proxy_url for proxy in proxies],
            'access_ip': [proxy.access_ip for proxy in proxies],
            'node_ip': [proxy.node_ip for proxy in proxies],
            'country': [proxy.country for proxy in proxies],
            'protocol': [proxy.protocol for proxy in proxies],
            'status': [proxy.status for proxy in proxies],
            'device_ip': [proxy.device_ip for proxy in proxies],
            'tag': [proxy.tag for proxy in proxies],
            'flag': [proxy.flag for proxy in proxies],
            'note': [proxy.note for proxy in proxies],
            'gateway': [proxy.gateway for proxy in proxies]
        }


    elif table_name == 'relay_connections':
        relay_connections = db.session.query(RelayConnection).all()
        # 创建 DataFrame 对象
        data = {
            'id': [relay.id for relay in relay_connections],
            'protocol': [relay.protocol for relay in relay_connections],
            'source_port': [relay.source_port for relay in relay_connections],
            'target_ip': [relay.target_ip for relay in relay_connections],
            'target_port': [relay.target_port for relay in relay_connections],
            'status': [relay.status for relay in relay_connections],
            'tag': [relay.tag for relay in relay_connections],
            'note': [relay.note for relay in relay_connections]
        }

    elif table_name == 'conversion':
        # 查询数据库
        convers = Conver.query.all()

        # 创建 DataFrame 对象
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
            'tag': [conv.tag for conv in convers],
            'status': [conv.status for conv in convers],
            'flag': [conv.flag for conv in convers]
        }
    elif table_name == 'host':
        # 查询数据库
        hosts = Host.query.all()
        # 创建 DataFrame 对象
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


    df = pd.DataFrame(data)
    # 创建 Excel 文件
    excel_data = BytesIO()
    with pd.ExcelWriter(excel_data, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)

    excel_data.seek(0)

    # 返回 Excel 文件
    return send_file(excel_data, attachment_filename=f'{table_name}.xlsx', as_attachment=True)


def import_excel(uploaded_file, table_name):
    try:
        df = pd.read_excel(uploaded_file, engine='openpyxl')
        # 删除空行
        df = df.dropna(how='all')  # 只删除所有列都为 NaN 的行
    except Exception as e:
        logging.error(f'读取Excel文件时出错: {e}')

    # 清空相应的数据库表中的数据
    if table_name == 'proxy_devices':
        ProxyDevice.query.delete()
    elif table_name == 'relay_connections':
        RelayConnection.query.delete()
    elif table_name == 'host':
        Host.query.delete()
    elif table_name == 'conversion':
        Conver.query.delete()

    # 用于存储要提交的记录
    records = []

    # 遍历 DataFrame 中的每一行，并将数据插入记录中
    for index, row in df.iterrows():
        if table_name == 'proxy_devices':
            record = ProxyDevice(
                proxy_url=row['proxy_url'],
                access_ip=row['access_ip'],
                node_ip=row['node_ip'],
                country=row['country'],
                protocol=row['protocol'],
                status=row['status'],
                device_ip=row['device_ip'],
                tag=row['tag'],
                flag=row['flag'],
                note=row['note'],
                gateway=row['gateway']
            )
        elif table_name == 'relay_connections':
            record = RelayConnection(
                protocol=row['protocol'],
                source_port=row['source_port'],
                target_ip=row['target_ip'],
                target_port=row['target_port'],
                status=row['status'],
                tag=row['tag'],
                note=row['note']
            )

        elif table_name == 'host':
            # 处理日期字段
            date_value = row['day'].date()
            record = Host(
                user=row['user'],
                country=row['country'],
                day=date_value,
                ip=row['ip'],
                account=row['account'],
                password=row['password'],
                port=row['port'],
                website=row['website'],
                remark=row['remark'],
                active=row['active']
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
                tag=row['tag'],
                status=row['status'],
                flag=row['flag']
            )

        records.append(record)

    # 使用 bulk_save_objects 方法批量提交记录
    try:
        db.session.bulk_save_objects(records)
        db.session.commit()
        if table_name == 'proxy_devices':
            excel_import_device_route_handler()
        logging.info(f"导入{table_name}数据表成功")
    except Exception as e:
        db.session.rollback()
        logging.info(f"导入{table_name}数据表失败")
