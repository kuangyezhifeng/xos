# monitoring.py
import time
import threading
import psutil
from flask_socketio import SocketIO
from app import create_app

app = create_app()
socketio = SocketIO(app)

realtime_data = {
    'cpu': 0,
    'memory': 0,
    'upload': 0,
    'download': 0
}

def get_system_data():
    while True:
        # 获取 CPU 使用率
        cpu_percent = psutil.cpu_percent(interval=1)

        # 获取内存使用率
        memory_percent = psutil.virtual_memory().percent

        # 获取所有网络接口的流量统计信息
        network_stats = psutil.net_io_counters(pernic=True)

        # 计算实时上传和下载速度，排除回环接口（lo）
        upload_speed = 0
        download_speed = 0
        for interface, stats in network_stats.items():
            if interface != 'lo':  # 排除回环接口
                upload_speed += stats.bytes_sent
                download_speed += stats.bytes_recv

        # 在适当的地方等待一段时间
        time.sleep(1)

        # 再次获取网络流量统计信息
        network_stats2 = psutil.net_io_counters(pernic=True)
        upload_speed2 = 0
        download_speed2 = 0
        for interface, stats in network_stats2.items():
            if interface != 'lo':  # 排除回环接口
                upload_speed2 += stats.bytes_sent
                download_speed2 += stats.bytes_recv

        # 计算实时上传和下载速度
        upload_speed = (upload_speed2 - upload_speed) / 1  # 1 秒的时间间隔
        download_speed = (download_speed2 - download_speed) / 1

        # 更新实时数据
        realtime_data['cpu'] = cpu_percent
        realtime_data['memory'] = memory_percent
        realtime_data['upload'] = upload_speed
        realtime_data['download'] = download_speed

        # 向前端推送实时数据
        socketio.emit('update_realtime_data', realtime_data)

# SocketIO 事件，用于向前端发送实时数据
@socketio.on('get_realtime_data')
def get_realtime_data():
    socketio.emit('update_realtime_data', realtime_data)

# 启动获取系统数据的线程
data_thread = threading.Thread(target=get_system_data)
data_thread.start()


