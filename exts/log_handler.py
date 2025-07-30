import os

def read_log(log_type, lines=30, from_offset=None):
    log_files = {
        'xos_log': '/var/log/xos.txt',
        'xray_access_log': '/var/log/xray/access.log',
        'xray_error_log': '/var/log/xray/error.log',
    }

    log_path = log_files.get(log_type)
    if not log_path:
        return f"Log type '{log_type}' not recognized.", 0

    if not os.path.exists(log_path):
        return f"Log file '{log_path}' not found.", 0

    if from_offset is not None:
        # 增量读取：从指定偏移读取至文件结尾
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(from_offset)
                content = f.read()
                end_offset = f.tell()
            return content, end_offset
        except Exception as e:
            return f"Error reading log from offset: {e}", 0

    # 初始加载：读取最后 lines 行（倒读文件）
    try:
        with open(log_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            block_size = 1024
            data = b''
            lines_found = 0
            pos = file_size
            while pos > 0 and lines_found < lines:
                read_size = min(block_size, pos)
                pos -= read_size
                f.seek(pos)
                block = f.read(read_size)
                data = block + data
                lines_found = data.count(b'\n')

            # 取最后 lines 行
            lines_data = data.splitlines()[-lines:]
            result = b'\n'.join(lines_data).decode('utf-8', errors='ignore')
            return result, file_size
    except Exception as e:
        return f"Error reading log: {e}", 0
