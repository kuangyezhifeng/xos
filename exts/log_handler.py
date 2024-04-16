# log_handler.py

def read_log(log_type, lines=100):
    log_files = {
        'xos_log': '/var/log/xos.txt',
        'xray_log': '/var/log/xray/access.log',
        'xray_error_log': '/var/log/xray/error.log',
    }

    log_path = log_files.get(log_type)
    if log_path:
        try:
            with open(log_path, 'r') as file:
                # 读取文件的最后指定行数
                log_content = "".join(file.readlines()[-lines:])
            return log_content
        except FileNotFoundError:
            return f"Log file '{log_path}' not found."
    else:
        return f"Log type '{log_type}' not recognized."
