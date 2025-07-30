# coding=utf-8
# 依赖程序sshpass socat  ssh-keygen -t rsa -b 2048
from flask import render_template, send_file, request, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from exts.host import *
from exts.hysteria2 import *
from exts.log_handler import *
from exts.conversion import *
from exts.excel import *
from exts.socks import alone_socks_config, alone_proxy_url, alone_running_socks, alone_noauth_socks_config
import pandas as pd
from sqlalchemy import case
from app import create_app
import psutil
import threading

app, socketio = create_app()
Migrate(app=app, db=db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
PER_PAGE = 50

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
        realtime_data['cpu'] = int(cpu_percent)
        realtime_data['memory'] = int(memory_percent)
        realtime_data['upload'] = int(upload_speed)
        realtime_data['download'] = int(download_speed)

        # 向前端推送实时数据
        socketio.emit('update_realtime_data', realtime_data)

# SocketIO 事件，用于向前端发送实时数据
@socketio.on('get_realtime_data')
def get_realtime_data():
    socketio.emit('update_realtime_data', realtime_data)


# 用户加载回调函数
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


# 注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not email or not password or not confirm_password:
            flash("请填写所有字段！", "error")
            return render_template('error.html')

        if password != confirm_password:
            flash('两次密码输入不一致', 'error')
            return render_template('register.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("用户名已被注册！", "error")
            return render_template('error.html')

        new_user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        # 使用 login_user 将用户登录
        login_user(new_user)
        return redirect(url_for('dashboard'))

    return render_template('register.html')


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("请输入用户名和密码！", "error")
            return render_template('login.html')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/update', methods=['GET'])
@login_required
def update():
    # 启动一个新线程执行更新操作
    threading.Thread(target=update_handler).start()
    # 重定向到 dashboard 页面
    return redirect(url_for('dashboard', user=current_user))


# 用于更改密码的路由
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the current password is correct
        if not current_user.check_password(current_password):
            flash('当前密码输入不正确', 'error')
        elif new_password != confirm_password:
            flash('两次密码输入不一致', 'error')
        else:
            # Set a new password and submit it to the database
            current_user.set_password(new_password)
            db.session.commit()
            return redirect(url_for('dashboard'))  # Redirects to the user's profile page

    return render_template('change_password.html')


# 注销路由
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# 路由主页面
@app.route('/', methods=['GET'])
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)

    # 按 gateway 降序，status 优先 Active
    status_order = case(
        (ProxyDevice.status == 'Active', 1),
        (ProxyDevice.status == 'Inactive', 2),
        else_=3
    )
    proxies = ProxyDevice.query.order_by(
        ProxyDevice.gateway.desc(),
        status_order
    ).paginate(page=page, per_page=PER_PAGE)

    user = current_user  # 加这一行，获取当前登录用户

    return render_template('dashboard.html', proxies=proxies, user=user)  # 把 user 传给模板
# @app.route('/logs/<log_type>')
# @login_required
# def logs(log_type):
#     # 读取日志文件的内容
#     log_content = read_log(log_type)
#
#     # 渲染模板并传递日志内容
#     return render_template('logs.html', log_content=log_content, log_type=log_type)
@app.route('/logs/<log_type>')
@login_required
def logs(log_type):
    # 读取日志文件的内容
    log_content = read_log(log_type)

    # 渲染静态页面（不再区分 Ajax）
    return render_template('logs.html', log_content=log_content, log_type=log_type)

@app.route('/error')
@login_required
def error():
    return render_template('error.html', user=current_user)


@app.route('/system', methods=['GET'])
@login_required
def system():
    exec_type = request.args.get('exec_type')
    # Mapping of exec_types to functions
    exec_type_functions = {
        'xos': (restart_xos_service,),
        'xray': (
            reset_xray_config,
            lambda: logging.info("Xray服务已经运行!") if is_xray_enabled() else reset_xray_services()),
        'restart': (lambda: restart_xray_service('xray'),),
    }

    try:
        for func in exec_type_functions.get(exec_type, ()):
            func()

    except Exception as e:
        logging.error(f"执行系统操作时发生错误: {str(e)}")

    return redirect(url_for('dashboard', user=current_user))


@app.route('/database', methods=['GET'])
@login_required
def database():
    type_class = request.args.get('type')
    if type_class  == "all":
        db.session.query(ProxyDevice).delete()
        db.session.query(RelayConnection).delete()
        db.session.query(Conver).delete()
        db.session.commit()

    elif type_class  == "proxy":
        db.session.query(ProxyDevice).delete()
        db.session.commit()
        return redirect(url_for('dashboard', user=current_user))

    elif type_class  == "forward":
        db.session.query(RelayConnection).delete()
        db.session.commit()
        return redirect(url_for('relay_connections', user=current_user))

    elif type_class  == "conversion":
        db.session.query(Conver).delete()
        db.session.commit()
        return redirect(url_for('conversion', user=current_user))

    elif type_class  == "host":
        db.session.query(Host).delete()
        db.session.query(Host_Config).delete()
        db.session.commit()
        return redirect(url_for('host', user=current_user))


@app.route('/gateway_select', methods=['GET', 'POST'])
@login_required
def gateway_select():
    if request.method == 'GET':
        target_ips_with_selection = gateway_route_config()
        return render_template('gateway.html', user=current_user, target_ips=target_ips_with_selection)

    elif request.method == 'POST':
        selected_target_ips = set(request.form.getlist('selected_target_ip'))
        gateway_route_savedb(selected_target_ips)

        return redirect(url_for('dashboard', user=current_user))


@app.route('/xos_config', methods=['GET', 'POST'])
@login_required
def xos_config():
    if request.method == 'GET':
        # 查询数据库中的配置信息
        config = Xos_config.query.first()

        # 如果数据库中没有配置信息，则插入一条默认记录
        if not config:
            default_config = Xos_config()
            db.session.add(default_config)
            db.session.commit()
            config = default_config
        return render_template('xos_set.html', user=current_user,config=config)

    elif request.method == 'POST':
        # 获取代理模式的选择值
        proxy_mode = request.form.get('proxy_mode')
        if proxy_mode:
            switch_proxy_mode(proxy_mode)
        # 获取代理分享的选择值
        proxy_share = request.form.get('proxy_share')
        if proxy_share:
            switch_proxy_share(proxy_share)

        # 获取页面行数的选择值
        page_rows = request.form.get('page_rows')
        if page_rows:
            set_page_number(page_rows)

        return redirect(url_for('dashboard', user=current_user))

"""

proxy_add 路由处理函数

功能描述：
proxy_add 路由处理函数用于处理 /proxy_add 路由的 GET 和 POST 请求。
在 GET 请求中，获取协议参数，并在渲染页面时执行一些初始化的操作。
在 POST 请求中，获取用户提交的代理节点信息（proxy_url 和 protocol），调用 create_node_handler 处理代理节点的创建。
处理完后，重定向到 dashboard 路由。

"""


@app.route('/proxy_add', methods=['GET', 'POST'])
@login_required
def create_node():
    if request.method == 'GET':
        # 获取协议参数
        node_type = request.args.get('protocol')

        # 可以在 GET 请求时执行一些初始化的操作
        return render_template('proxy_add.html', user=current_user, protocol=node_type)
    else:
        protocol = request.form.get('protocol')
        # 获取以回车分隔的多行代理 URL
        proxy_urls = request.form.get('proxy_url').split('\n')
        for proxy_url in proxy_urls:
            proxy_url = proxy_url.strip()  # 去除空格和换行符
            if not proxy_url:
                continue  # 跳过空行
            # 由handle_proxy根据协议不同做处理
            result = create_node_handler(proxy_url, protocol)
            if not result:
                continue
            else:
                flash(f'协议连接无法创建请确认格式', 'error')
                return redirect(url_for('error', user=current_user))

    return redirect(url_for('dashboard', user=current_user))


"""
proxy_on_off 路由处理函数

功能描述：
proxy_on_off 路由处理函数用于处理 /proxy_on_off 路由的 GET 请求。
获取请求参数中的 ID，根据 ID 查询代理设备信息。
获取代理设备的相关信息，如 proxy_url、outbound_tag 和 flag。
根据 flag 的值，调用 xray_node_outbound_add 或 xray_node_outbound_remove 处理代理节点的启用或停用。
处理完后，更新代理设备的 flag 字段，并提交更改到数据库。
调用 restart_xray_service 重启 Xray 服务。
处理完后，重定向到 dashboard 路由。
"""


# 启动分流代理程序
@app.route('/proxy_on_off', methods=['GET', 'POST'])
@login_required
def node_on_off():
    if request.method == 'GET':
        id = request.args.get('id')
        proxies = db.session.get(ProxyDevice, id)
        if proxies is None:
            # 这里可以处理没查到的情况，比如返回错误或跳过
            return "ProxyDevice not found", 404
        set_config(proxies)

    else:
        selected_items = request.form.getlist('selected_items[]')
        for id in selected_items:
            proxies = db.session.get(ProxyDevice, id)
            if proxies is None:
                # 处理异常，比如跳过该id继续
                continue
            set_config(proxies)

    return redirect(url_for('dashboard'))




"""
bind_device 路由处理函数

功能描述：
bind_device 路由处理函数用于处理 /bind_device 路由的 GET 和 POST 请求。
在 GET 请求中，根据传入的 ID 查询主 IP 信息，获取代理设备的信息。
在 POST 请求中，获取用户提交的原始文本，调用 xray_device_route_handler 处理该设备的路由信息。
如果处理成功，则重定向到 dashboard 路由。
如果处理失败，则重定向回 bind_device 路由。

"""


@app.route('/bind_device', methods=['GET', 'POST'])
@login_required
def bind_device():
    # 根据ID查询主IP信息
    id = request.args.get('id', type=int)
    # 查询数据库，获取数据
    proxys = ProxyDevice.query.filter_by(id=id).first()

    if request.method == 'POST':
        raw_text = request.form.get('mytextarea')
        result = xray_device_route_handler(proxys, raw_text)

        if result['success']:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('bind_device', user=current_user, id=id))

    # 获取 device_ip 的最新值
    device_ip = proxys.device_ip
    return render_template('ip.html', user=current_user, id=id, ips=device_ip or '')


"""
node_update 路由处理函数

功能描述：
node_update 路由处理函数用于处理 /proxy_update 路由的 GET 和 POST 请求。
在 GET 请求中，根据传入的 ID 查询代理设备信息，渲染代理设备更新的模板。
在 POST 请求中，获取用户提交的更新信息，根据 ID 查询代理设备信息，更新相应字段的值，然后提交更改。
处理完 POST 请求后，重定向到 dashboard 路由。

"""


@app.route('/proxy_update', methods=['GET', 'POST'])
@login_required
def node_update():
    if request.method == 'GET':
        id = request.args.get('id')
        # 根据ID查询代理设备信息
        proxy_device = db.session.get(ProxyDevice, id)
        return render_template('proxy_update.html', user=current_user, proxy_device=[proxy_device])

    else:
        id = request.form.get('id')
        node_ip = request.form.get('node_ip')
        country = request.form.get('country')
        protocol = request.form.get('protocol')
        note = request.form.get('note')

        # 根据ID找到要修改的代理设备
        proxy_device = db.session.get(ProxyDevice, id)

        # 更新指定字段的值
        proxy_device.node_ip = node_ip
        proxy_device.country = country
        proxy_device.protocol = protocol
        proxy_device.note = note

        # 提交更改
        db.session.commit()

        return redirect(url_for('dashboard', user=current_user))


"""
node_delete 路由处理函数

功能描述：
node_delete 路由处理函数用于处理 /proxy_delete 路由的 GET 请求。
获取请求参数中的 ID，根据 ID 查询代理设备信息。
调用 xray_node_delete_handler 处理删除代理节点的操作。
处理完后，重定向到 dashboard 路由。
"""


@app.route('/proxy_delete', methods=['GET', 'POST'])
@login_required
def node_delete():
    id = request.args.get('id')

    if id:
        proxy_device = db.session.get(ProxyDevice, id)
        xray_node_delete_handler(proxy_device)

    else:
        selected_items = request.form.getlist('selected_items[]')
        for id in selected_items:
            proxies = db.session.get(ProxyDevice, id)
            xray_node_delete_handler(proxies)
            logging.info(f'✅已删除代理:{proxies.access_ip} 路由:{proxies.tag}')

    return redirect(url_for('dashboard'))


"""

get_ip_info 路由处理函数
功能描述：

get_ip_info 路由处理函数用于处理 /get_ip_info 路由的 GET 请求。
在 GET 请求中，根据请求参数判断是根据 ID 获取代理 IP 信息，还是获取所有未获取过 IP 信息的代理。
如果传入了 id 参数，则获取对应 ID 的代理信息，调用 xray_proxies_info_handler 处理该代理的 IP 信息。
如果没有传入 id 参数，则获取所有未获取过 IP 信息的代理，逐一调用 xray_proxies_info_handler 处理每个代理的 IP 信息。
最后，重定向到 dashboard 路由。
"""


# 获取代理IP信息
@app.route('/get_ip_info', methods=['GET', 'POST'])
@login_required
def get_ip_info():
    if request.method == 'GET':
        # 获取所有代理 URL，取node_ip字段的为空的代理
        proxy_ids = [proxy.id for proxy in ProxyDevice.query.filter_by(flag=1).all()]
        xray_proxies_info_handler(proxy_ids)

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        xray_proxies_info_handler(selected_items)

    return redirect(url_for('dashboard'))


"""
relay_connections 路由处理函数
功能描述：

relay_connections 路由处理函数用于处理 /relay_connections 路由的 GET 和 POST 请求。
在 GET 请求中，从请求参数中获取 type 参数，如果 type 为 add，表示用户要添加中转规则，渲染添加中转规则的模板。
如果 type 不为 add 或未传递 type 参数，则渲染通用的中转规则模板。
在 POST 请求中，获取用户提交的中转规则文本，调用 check_relay_rules 函数验证规则的格式是否正确。
如果验证成功，则调用 relay_info_savedb 函数保存中转规则到数据库，然后重定向到 relay_connections 路由。
如果验证失败，将错误消息传递到模板，并在模板中显示用户输入的内容。
注意：

在 get_ip_info 路由处理函数中，根据传入的 ID 或者获取所有未获取过 IP 信息的代理，逐一调用 xray_proxies_info_handler 处理代理的 IP 信息。
在 relay_connections 路由处理函数中，处理 POST 请求时，根据验证结果执行不同的操作，要么保存到数据库，要么传递错误消息到模板。
"""


@app.route('/relay_connections', methods=['GET', 'POST'])
@login_required
def relay_connections():
    user = current_user
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)

        # 使用 paginate 方法获取一个分页对象
        connections = RelayConnection.query.order_by(-RelayConnection.source_port).paginate(page=page,
                                                                                            per_page=PER_PAGE)
        # 检查请求的页码是否超过实际页数
        if page > connections.pages and connections.pages > 0:
            return redirect(url_for('relay_connections', page=connections.pages))

        # 获取type参数值，默认为None
        exec_type = request.args.get('type')

        if exec_type == 'add':
            # 渲染添加中转规则的模板
            return render_template('relay_ip.html', user=user, connections=connections)

        else:
            # 默认情况下渲染通用的中转规则模板
            return render_template('relay_connections.html', user=user, connections=connections)

    else:
        relay_ip_text = request.form.get('mytextarea')
        result, rules = check_relay_rules(relay_ip_text)

        if result:
            # 验证成功，保存数据到数据库
            relay_info_savedb(rules)
            return redirect(url_for('relay_connections'))

        else:
            # 验证失败，将错误消息传递到模板
            flash("规则格式错误: {}".format(rules), 'error')
            # 传递参数到模板以显示之前用户输入的内容
            return render_template('error.html', user=user)


"""
relay_on_off 路由处理函数

功能描述：
relay_on_off 路由处理函数用于处理 /relay_on_off 路由的 GET 和 POST 请求。
在 GET 请求中，从请求参数中获取 relay_id 和 exec_type。
如果 relay_id 存在，表示操作单个中转规则；否则，表示操作所有中转规则。
在 POST 请求中，根据 relay_id 是否存在，选择操作单个中转规则或所有中转规则。
调用 process_single_relay 函数执行中转规则的启用/禁用/删除操作。
提交更改到数据库，并记录成功的消息。
最后，重定向到 relay_connections 路由。
"""


@app.route('/relay_on_off', methods=['GET', 'POST'])
@login_required
def relay_on_off():
    if request.method == 'GET':
        relay_id = request.args.get('id')
        # 获取type参数值，默认为None
        exec_type = request.args.get('type')

        if relay_id:
            relay_connection = db.session.get(RelayConnection, relay_id)
            if relay_connection:
                process_single_relay(relay_connection, exec_type)
        else:
            relay_connections = RelayConnection.query.all()
            for relay_connection in relay_connections:
                process_single_relay(relay_connection, exec_type)

    elif request.method == 'POST':

        selected_items = request.form.getlist('selected_items[]')
        exec_type = request.args.get('type')
        for id in selected_items:
            relay_connection = db.session.get(RelayConnection, id)
            if relay_connection is None:
                # 处理未找到记录的逻辑
                raise ValueError(f"RelayConnection with id {id} not found")
            process_single_relay(relay_connection, exec_type)

    return redirect(url_for('relay_connections'))


"""
relay_update 路由处理函数

功能描述：
relay_update 路由处理函数用于处理 /relay_update 路由的 GET 和 POST 请求。
在 GET 请求中，从请求参数中获取 id，查询并渲染与该 id 对应的中转规则信息。
在 POST 请求中，从表单中获取更新后的中转规则信息，更新数据库中对应的中转规则。
提交更改到数据库，并重定向到 relay_connections 路由。
注意： 在处理 relay_update 路由时，使用了两个请求方法的区分，分别执行获取和更新中转规则的操作。在更新中转规则时，通过查询 RelayConnection 表并使用表单数据更新相应的字段。
"""


@app.route('/relay_update', methods=['GET', 'POST'])
@login_required
def relay_update():
    if request.method == 'GET':
        id = request.args.get('id')
        relay_info = db.session.get(RelayConnection, id)
        return render_template('relay_update.html', user=current_user, relay_connections=[relay_info])

    elif request.method == 'POST':
        id = request.form.get('id')
        relay_info = db.session.get(RelayConnection, id)
        relay_info.protocol = request.form.get('protocol')
        relay_info.source_port = request.form.get('source_port')
        relay_info.target_port = request.form.get('target_port')
        relay_info.note = request.form.get('note')

        db.session.commit()

        return redirect(url_for('relay_connections'))


"""

relay_ip_select 路由处理函数

功能描述：
relay_ip_select 路由处理函数用于处理 /relay_ip_select 路由的 GET 和 POST 请求。
在 GET 请求中，从请求参数中获取 tag，并使用 relay_ip_route_config 函数获取目标 IP 信息。
将结果传递给名为 relay_ip_select.html 的模板进行渲染，并在模板中显示目标 IP 列表。
在 POST 请求中，从表单中获取 tag 和选中的目标 IP 列表，然后调用 relay_ip_route_set 函数更新数据库中的中转规则。
最后，重定向到 dashboard 路由。
"""

@app.route('/proxy_chain', methods=['GET', 'POST'])
@login_required
def proxy_chain():
    # 处理 GET 请求逻辑
    tag = request.args.get('tag')
    id = request.args.get('id', type=int)
    if request.method == 'POST':
        selected_value = request.form.get('selected_target_ip')  # 格式 "ip|tag" 或 None
        id = request.args.get('id', type=int)
        device = db.session.get(ProxyDevice, id)


        if selected_value:
            selected_ip, selected_tag = selected_value.split('|')
            device.proxy_chain = selected_tag
            set_proxy_chain(get_tag=tag, post_tag=selected_tag)

        else:
            # 只有id，没有选中，清空字段
            device.proxy_chain = None
            clear_proxy_chain(tag)

        db.session.commit()
        # 处理完后，跳转回GET页面，传选中ip的tag和id
        return redirect(url_for('dashboard', user=current_user))

    # 查询符合条件的数据
    devices = ProxyDevice.query.with_entities(ProxyDevice.node_ip, ProxyDevice.tag) \
        .filter(ProxyDevice.status == 'Active') \
        .filter((ProxyDevice.proxy_chain == None) | (ProxyDevice.proxy_chain == '')) \
        .filter(ProxyDevice.access_ip != '127.0.0.1') \
        .all()
    # 构造模板需要的结构 (node_ip, tag, selected)
    target_ips = [(node_ip, dev_tag, False) for node_ip, dev_tag in devices]

    return render_template('proxy_chain.html',
                           user=current_user,
                           target_ips=target_ips,
                           tag=tag,
                           id=id)




"""
test_all_ports 路由处理函数
功能描述：

test_all_ports 路由处理函数用于处理 /test_all_ports 路由的 GET 请求。
获取所有中转规则记录，并对每个规则执行端口测试。
如果连接成功，表示端口可用，不进行任何测试。
如果连接失败，更新记录的 status 字段为 "fail"。
最后，提交更改到数据库，并重定向到 relay_connections 路由。

操作步骤：
获取所有中转规则记录。
对每个中转规则执行端口测试。
如果连接成功，表示端口可用，不进行任何测试。
如果连接失败，更新记录的 status 字段为 "fail"。
提交更改到数据库。
记录成功测试并更新的消息。
重定向到 relay_connections 路由。
注意： 在测试端口时，使用了 socket.create_connection 函数，如果连接失败，将捕获 socket.timeout 和 ConnectionRefusedError 
异常。在记录错误日志时，需要确保记录有足够的信息以便于排查问题。
"""


@app.route('/test_all_ports', methods=['GET', 'POST'])
@login_required
def test_all_ports():
    relay_connections = RelayConnection.query.all()

    for connection in relay_connections:
        target_ip = connection.target_ip
        target_port = connection.target_port

        try:
            # 构造测试命令
            test_command = [
                "sudo", "-u", "xray",
                "python3", "-c",
                f"import socket; "
                f"s = socket.create_connection(('{target_ip}', {target_port}), timeout=5); "
                f"s.close()",
            ]

            # 运行测试命令
            subprocess.run(test_command, check=True)

        except (subprocess.CalledProcessError, socket.timeout, ConnectionRefusedError):
            # 如果命令运行失败或连接超时或被拒绝，更新记录的 note 字段
            update_status = "已关闭"
            db.session.commit()
            connection.status = f"{connection.note}\n{update_status}" if connection.note else update_status
            # 抑制异常，继续测试下一个端口
            logging.error(f"测试端口关闭: {target_ip}:{target_port}")

    logging.info("成功测试并更新所有端口状态")
    return redirect(url_for('relay_connections'))


"""
主机部分
"""



# 协议转换部分
@app.route('/conversion', methods=['GET', 'POST'])
@login_required
def conversion():
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)

        # 使用 paginate 方法获取一个分页对象，并按照状态排序
        proxies = Conver.query.order_by(Conver.status,Conver.country).paginate(page=page, per_page=PER_PAGE)

        # 检查请求的页码是否超过实际页数
        if page > proxies.pages and proxies.pages > 0:
            return redirect(url_for('conversion', page=proxies.pages))

        return render_template('conversion.html', user=current_user, proxies=proxies)

    else:
        relay_ip_text = request.form.get('mytextarea')
        result, rules = check_relay_rules(relay_ip_text)

        if result:
            # 验证成功，保存数据到数据库
            relay_info_savedb(rules)
            return redirect(url_for('conversion'))  # 跳转到 conversion 页面

        else:
            # 验证失败，将错误消息传递到模板
            flash("转换规则错误: {}".format(rules), 'error')
            # 传递参数到模板以显示之前用户输入的内容
            return render_template('error.html', user=current_user)



@app.route('/conversion_create', methods=['GET', 'POST'])
@login_required
def conversion_create():
    if request.method == 'GET':
        # 可以在 GET 请求时执行一些初始化的操作
        return render_template('conversion_create.html', user=current_user)
    else:
        # 获取表单数据
        inbound_protocol = request.form.get('inbound_protocol')
        outbound_protocol = request.form.get('outbound_protocol')

        # 获取以回车分隔的多行代理 URL
        proxy_urls = [url.strip() for url in request.form.get('proxy_url').split('\n')]
        generate_conversions(inbound_protocol, outbound_protocol, proxy_urls)
        return redirect(url_for('conversion', user=current_user))


@app.route('/conversion_on_off', methods=['GET', 'POST'])
@login_required
def conversion_on_off():
    # 根据ID查询主IP信息
    if request.method == 'GET':
        id = request.args.get('id')
        proxy = db.session.get(Conver, id)
        conversion_config(proxy)

    else:
        selected_items = request.form.getlist('selected_items[]')
        for id in selected_items:
            proxies = Conver.query.get(id)
            conversion_config(proxies)

    return redirect(url_for('conversion'))


@app.route('/conversion_update', methods=['GET', 'POST'])
@login_required
def conversion_update():

    if request.method == 'GET':
        id = request.args.get('id')
        # 根据ID查询代理设备信息
        conversions = Conver.query.get(id)
        return render_template('conversion_update.html', user=current_user, conver=[conversions])

    else:
        id = request.form.get('id')
        proxy_ip = request.form.get('proxy_ip')
        protocol = request.form.get('protocol')
        inbound = request.form.get('inbound_connections')
        outbound = request.form.get('outbound_connections')
        tag = request.form.get('tag')
        # 根据 ID 获取要更新的记录
        conver = Conver.query.get(id)
        if conver:
            # 更新字段值
            conver.proxy_ip = proxy_ip
            conver.protocol = protocol
            conver.inbound_connections = inbound
            conver.outbound_connections = outbound
            conver.tag = tag

            # 提交更改
            db.session.commit()
        return redirect(url_for('conversion', user=current_user))


@app.route('/conversion_enable', methods=['GET', 'POST'])
@login_required
def conversion_enable():
    # 查询所有flag字段为1的条目
    conversions = Conver.query.filter_by(flag=1).all()

    # 提取所需字段的数据
    result = []
    for conversion in conversions:
        result.append({
            'protocol': conversion.outbound_protocol,
            'tag': conversion.tag,
            'inbound_connections': conversion.inbound_connections,
            'outbound_connections': conversion.outbound_connections
        })
    # 调用 conversion_start() 函数处理数据
    conversion_start(result)
    return redirect(url_for('conversion'))

@app.route('/conversion_disable', methods=['GET', 'POST'])
@login_required
def conversion_disable():
    try:
        # 使用 subprocess 执行停止服务的命令
        subprocess.run(['systemctl', 'stop', 'conversion'], check=True)
        # 记录日志
        logging.info('协议转换服务成功停止')
        return redirect(url_for('conversion'))

    except subprocess.CalledProcessError:
        # 记录日志
        logging.error('协议转换停止服务失败')
        return redirect(url_for('conversion'))

@app.route('/conversion_check', methods=['GET', 'POST'])
@login_required
def conversion_check():
    if request.method == 'GET':
        id = request.args.get('id')
        # 根据ID查询代理设备信息
        conversion_check_proxy([id])  # 将单个 ID 包装成列表

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        conversion_check_proxy(selected_items)

    return redirect(url_for('conversion'))


@app.route('/conversion_delete', methods=['GET', 'POST'])
@login_required
def conversion_delete():
    id = request.args.get('id')
    if id:
        conver = Conver.query.get(id)
        if conver:
            db.session.delete(conver)
            db.session.commit()
            logging.info(f'✅删除协议转换:{conver.inbound_connections} 路由:{conver.outbound_connections}')

    else:
        selected_items = request.form.getlist('selected_items[]')
        for id in selected_items:
            conver = Conver.query.get(id)
            db.session.delete(conver)
            logging.info(f'✅删除协议转换:{conver.inbound_connections} 路由:{conver.outbound_connections}')
            db.session.commit()

    return redirect(url_for('conversion'))


@app.route('/conversion_select', methods=['GET', 'POST'])
@login_required
def conversion_select():
    if request.method == 'GET':
        return render_template('conversion_get.html', user=current_user)
    else:
        country = request.form.get('country')
        city = request.form.get('city')
        inbound_protocol = request.form.get('inbound_protocol')
        outbound_protocol = request.form.get('outbound_protocol')
        status = request.form.get('status')
        # 调用提取数据的函数
        results = extract_conversion_data(country, city, inbound_protocol, outbound_protocol, status)

        # 初始化连接列表
        connections = []
        # 根据条件判断入站和/或出站协议是否为真
        for item in results:
            if inbound_protocol and outbound_protocol:  # 如果入站和出站协议都为真
                # 返回入站和出站连接
                connections.append({
                    'inbound_connection': item.inbound_connections,
                    'outbound_connection': item.outbound_connections
                })
            elif inbound_protocol:  # 如果只有入站协议为真
                # 返回入站连接
                connections.append({
                    'inbound_connection': item.inbound_connections
                })
            elif outbound_protocol:  # 如果只有出站协议为真
                # 返回出站连接
                connections.append({
                    'outbound_connection': item.outbound_connections
                })
            else:  # 如果入站和出站协议都为假
                # 返回空连接
                connections.append({})
        # 渲染模板并传递数据
        return render_template('conversion_get.html', connections=connections, user=current_user)


@app.route('/host')
@login_required
def host():
    page = request.args.get('page', 1, type=int)
    # 假设 PER_PAGE 是一个常量，定义每页显示的条目数
    hosts = Host.query.order_by(Host.day.desc()).paginate(page=page, per_page=PER_PAGE)

    # 检查请求的页码是否超过实际页数
    if page > hosts.pages and hosts.pages > 0:
        return redirect(url_for('host', page=hosts.pages))

    return render_template('host.html', user=current_user, hosts=hosts)


@app.route('/host_create', methods=['POST', 'GET'])
@login_required
def host_create():
    if request.method == 'POST':
        form_data = request.form.to_dict()

        # 将日期字符串转换为Python日期对象
        form_data['day'] = datetime.strptime(form_data['day'], '%Y-%m-%d').date()

        # 提取POST的数据插入数据库
        host_server = Host(**form_data)

        db.session.add(host_server)
        db.session.commit()

        return redirect(url_for('host'))

    return render_template('host_create.html', user=current_user)


@app.route('/host_status', methods=['GET', 'POST'])
@login_required
def host_status():
    if request.method == 'GET':
        host_record = Host.query.get(request.args.get('id'))
        if host_record:
            setup_ssh_key_authentication(host_record)

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        for host_id in selected_items:
            host_record = db.session.get(Host, host_id)
            setup_ssh_key_authentication(host_record)

    return redirect(url_for('host', user=current_user))


@app.route('/host_update', methods=['GET', 'POST'])
@login_required
def host_update():
    if request.method == 'POST':
        id = request.form.get('id')
        host = db.session.get(Host, id)
        if host:
            # 使用字典解析简化参数获取
            update_data = {key: request.form.get(key) for key in
                           ['user', 'country', 'day', 'ip', 'account', 'password', 'port', 'website', 'remark']}

            # 将字符串日期转换为日期对象
            update_data['day'] = datetime.strptime(update_data['day'], '%Y-%m-%d').date()
            # 手动更新属性
            for key, value in update_data.items():
                setattr(host, key, value)
            # 提交
            db.session.commit()

        return redirect(url_for('host', user=current_user))

    else:
        id = request.args.get('id')
        # 使用 first() 获取单个记录
        host = Host.query.filter(Host.id == id).first()
        return render_template('host_update.html', user=current_user, host=host)


@app.route('/host_delete', methods=['GET', 'POST'])
@login_required
def host_delete():
    if request.method == 'GET':
        host_record = Host.query.get(request.args.get('id'))
        # 删除 Host_Config 表中与主机关联的记录
        host_config_entries = Host_Config.query.filter_by(main_ip=host_record.ip).all()
        for entry in host_config_entries:
            db.session.delete(entry)
        # 删除主机和关联的代理信息
        db.session.delete(host_record)
        db.session.commit()

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        for host_id in selected_items:
            host_record = db.session.get(Host, host_id)
            # 删除 Host_Config 表中与主机关联的记录
            host_config_entries = Host_Config.query.filter_by(main_ip=host_record.ip).all()
            for entry in host_config_entries:
                db.session.delete(entry)
            # 删除主机和关联的代理信息
            db.session.delete(host_record)

        db.session.commit()

    return redirect(url_for('host'))


@app.route('/host_view', methods=['GET'])
@login_required
def host_view():
    host_id = request.args.get('id')
    host_record = Host.query.filter_by(id=host_id).first()
    page = request.args.get('page', 1, type=int)

    if host_record:
        # 直接在查询对象上使用 paginate 方法
        proxies_query = Host_Config.query.filter_by(main_ip=host_record.ip).paginate(page=page, per_page=PER_PAGE)

        if proxies_query.items:  # 检查结果中是否有数据
            return render_template('host_view.html', user=current_user, proxies=proxies_query, host_record=host_record)

    return render_template('error.html', message='未找到主机')


@app.route('/host_ips', methods=['GET', 'POST'])
@login_required
def host_ips():
    if request.method == 'GET':
        host_info = Host.query.get(request.args.get('id'))
        # 调用 get_remote_ip_addresses 函数
        ip = host_info.ip
        username = host_info.account
        passwd = host_info.password
        port = host_info.port
        get_remote_ip_addresses(ip, username, passwd, port)

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        for host_id in selected_items:
            host_info = db.session.get(Host, host_id)
            ip = host_info.ip
            username = host_info.account
            passwd = host_info.password
            port = host_info.port
            get_remote_ip_addresses(ip, username, passwd, port)
    return redirect(url_for('host', user=current_user))


@app.route('/proxies_update', methods=['GET', 'POST'])
@login_required
def proxies_update():
    id = request.args.get('id')
    proxies = Host_Config.query.get_or_404(id)

    if request.method == 'POST':
        proxies.user = request.form.get('user')
        proxies.protocol = request.form.get('protocol')
        proxies.speed_limit = request.form.get('speed_limit')
        proxies.proxy_url = request.form.get('proxy_url')
        created_at_str = request.form.get('created_at')
        expiration_date_str = request.form.get('expiration_date')

        if created_at_str:
            proxies.created_at = datetime.strptime(created_at_str, '%Y-%m-%d').date()
        else:
            # 处理日期为空的情况，例如设置默认值
            proxies.created_at = None  # 或者设置为默认日期

        if expiration_date_str:
            proxies.expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d').date()
        else:
            # 处理日期为空的情况，例如设置默认值
            proxies.expiration_date = None  # 或者设置为默认日期

        proxies.remark = request.form.get('remark')
        # 其他字段的类似代码
        db.session.commit()

        host_id = (
            db.session.query(Host.id)
            .filter(Host.ip == proxies.main_ip)
            .scalar()
        )

        return redirect(url_for('host_view', user=current_user, id=host_id))

    return render_template('proxies_update.html', user=current_user, proxies=proxies)


@app.route('/xray_install', methods=['GET', 'POST'])
@login_required
def xray_install():
    if request.method == 'GET':
        host_record = Host.query.get(request.args.get('id'))
        remote_host = host_record.ip.strip()
        xray_remote_service_handler(remote_host)

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        for host_id in selected_items:
            host_record = db.session.get(Host, host_id)
            remote_host = host_record.ip
            xray_remote_service_handler(remote_host)

    return redirect(url_for('host'))


@app.route('/host_proxies_test', methods=['GET', 'POST'])
@login_required
def host_proxies_test():
    # 根据ID查询主IP信息
    if request.method == 'GET':
        proxies_id = request.args.get('id')
        proxies = Host_Config.query.filter(Host_Config.id == proxies_id).all()
        batch_proxies_test(proxies)

        # 执行联结查询，只返回 host 表的 id 值
        host_id = db.session.query(Host.id). \
            join(Host_Config, Host_Config.main_ip == Host.ip). \
            filter(Host_Config.id == proxies_id).scalar()

        return redirect(url_for('host_view', id=host_id, user=current_user))

    elif request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        for host_id in selected_items:
            host_record = Host.query.filter_by(id=host_id).first()
            main_ip = host_record.ip
            # siggle_proxies_test(main_ip)
            # 根据主ip在Url表中查询相关URL信息
            proxies = Host_Config.query.filter(
                (Host_Config.main_ip == main_ip) &
                (Host_Config.proxy_url.isnot(None)) &
                (Host_Config.proxy_url != "") &
                (Host_Config.protocol.isnot(None)) &
                (Host_Config.protocol != "")
            ).all()

            batch_proxies_test(proxies)
        return redirect(url_for('host', user=current_user))

    return render_template('host_view.html', user=current_user)


@app.route('/proxies_delete', methods=['POST'])
def proxies_delete():
    if request.method == 'POST':
        selected_items = request.form.getlist('selected_items[]')
        # 执行联结查询，只返回 host 表的 id 值
        id = int(selected_items[0])
        host_id = db.session.query(Host.id). \
            join(Host_Config, Host_Config.main_ip == Host.ip). \
            filter(Host_Config.id == id).scalar()

        if selected_items:
            try:
                selected_ids = [int(item) for item in selected_items]
                Host_Config.query.filter(Host_Config.id.in_(selected_ids)).delete(synchronize_session=False)
                db.session.commit()
            except Exception as e:
                db.session.rollback()

        return redirect(url_for('host_view', id=host_id, user=current_user))

    return redirect(url_for('relay_connections'))


@app.route('/batch_create_proxies', methods=['GET', 'POST'])
@login_required
def batch_create_proxies():
    if request.method == 'GET':
        return render_template('batch_proxies_create.html', user=current_user)

    elif request.method == 'POST':
        protocol = request.form.get('optradio')
        unique_ips_list = [ip.strip() for ip in set(request.form.get('mytextarea').split('\n')) if ip.strip()]
        # 获取字段值，如果不存在则保留为 None
        port = request.form.get('port')
        account = request.form.get('account')
        password = request.form.get('password')

        # 调用函数
        batch_proxies_set(protocol, unique_ips_list, port, account, password)

        return redirect(url_for('host', user=current_user))


@app.route('/single_create_proxies', methods=['GET', 'POST'])
@login_required
def single_create_proxies():
    if request.method == 'GET':
        id = request.args.get('id')
        ip = Host_Config.query.get(id)

        return render_template('single_proxies_create.html', user=current_user, id=id, proxy_ip=ip)

    elif request.method == 'POST':
        protocol = request.form.get('optradio')
        id = request.form.get('id')
        # 根据ID值获取辅助IP用于构建proxy_url
        port = request.form.get('port', '10808')
        proxies = Host_Config.query.get(id)
        ip = proxies.auxiliary_ip
        # 创建SOCKS代理
        if protocol == 'socks':
            # 获取字段值
            account = request.form.get('account')
            password = request.form.get('password')
            # 如果字段为空，则使用默认值
            if account is None or not account.strip():
                account = generate_random_account()

            if password is None or not password.strip():
                password = generate_random_password()
            # 更新数据库字段
            proxies.protocol = protocol
            proxies.proxy_url = f"socks://{ip}:{port}:{account}:{password}"
            logging.info(f"✅成功创建新的代理:{proxies.proxy_url}")
            db.session.commit()

        # 创建VMESS代理
        elif protocol in ['vmess_tcp', 'vmess_kcp']:
            vmess_link = generate_vmess_link(protocol, ip, port)
            proxies.protocol = 'vmess'
            proxies.proxy_url = vmess_link
            logging.info(f"✅成功创建新的代理:{proxies.proxy_url}")
            db.session.commit()

        # 创建hysteria2代理
        elif protocol in ['hysteria2']:
            main_ip = proxies.main_ip
            user = db.session.query(Host).filter(Host.ip == main_ip).first()
            if user:
                account = user.account
            password = generate_random_password()
            proxies.protocol = 'hysteria2'
            proxies.proxy_url = f"hysteria2://{password}@{main_ip}:{port}?sni=bing.com&insecure=1#hyster2"
            logging.info(f"✅成功创建新的代理:{proxies.proxy_url}")
            db.session.commit()
            # 部署服务
            deploy_hysteria2(main_ip, account, password, port)

        # 执行联结查询，只返回 host 表的 id 值
        host_id = db.session.query(Host.id). \
            join(Host_Config, Host_Config.main_ip == Host.ip). \
            filter(Host_Config.id == id).scalar()
        return redirect(url_for('host_view', id=host_id, user=current_user))


@app.route('/batch_get_proxies', methods=['GET', 'POST'])
@login_required
def batch_get_proxies():
    if request.method == 'POST':
        unique_ips_list = [ip.strip() for ip in set(request.form.get('mytextarea').split('\n')) if ip.strip()]
        query_result = batch_get_proxies_info(unique_ips_list)

        return render_template('batch_get_proxies.html', user=current_user, query_result=query_result)

    return render_template('batch_get_proxies.html', user=current_user)


@app.route('/batch_speed_limit', methods=['GET', 'POST'])
@login_required
def batch_speed_limit():
    # 根据ID查询主IP信息
    id = request.args.get('id')
    main_ip = Host.query.get_or_404(id).ip

    # 查询所有limit字段不为空或为none的行
    proxies = Host_Config.query.filter(
        (Host_Config.speed_limit.notilike('%None%')) &  # 不匹配 "None"，不区分大小写
        (Host_Config.speed_limit.notilike('%none%')) &  # 不匹配 "none"，不区分大小写
        (Host_Config.speed_limit.isnot(None)) &  # 不匹配空值
        (Host_Config.speed_limit != '')  # 不匹配空字符串
    ).all()

    if proxies:
        create_tc_limit(main_ip, proxies)

    return redirect(url_for('host', user=current_user))


@app.route('/copy_record/<int:id>', methods=['GET', 'POST'])
@login_required
def copy_record(id):
    # 查询指定 id 的记录
    original_record = Host_Config.query.get_or_404(id)

    # 复制记录
    new_record = Host_Config(
        user=original_record.user,
        main_ip=original_record.main_ip,
        auxiliary_ip=original_record.auxiliary_ip,
    )
    # 插入新记录
    db.session.add(new_record)
    db.session.commit()
    logging.info("复制记录成功!")

    # 查询 Host 表中的 id，其中 Host 表中的 ip 等于 main_ip
    host_id = db.session.query(Host.id).filter(Host.ip == original_record.main_ip).scalar()

    return redirect(url_for('host_view', id=host_id, user=current_user))


@app.route('/export_excel_route/<table_name>')
@login_required
def export_excel_route(table_name):
    # 返回 Excel 文件
    return export_excel(table_name)

@app.route('/import_excel_route/<table_name>', methods=['GET', 'POST'])
@login_required
def import_excel_route(table_name):
    if request.method == 'GET':
        # 处理 GET 请求的逻辑
        return render_template('upload.html', table_name=table_name)

    elif request.method == 'POST':
        # 处理 POST 请求的逻辑
        uploaded_file = request.files['file']
        table_name = request.form.get('table_name')
        # 调用处理文件上传的函数
        import_excel(uploaded_file, table_name)

        if table_name == 'proxy_devices':
            return redirect(url_for('dashboard', user=current_user))
        elif table_name == 'relay_connections':
            return redirect(url_for('relay_connections', user=current_user))
        elif table_name == 'host':
            return redirect(url_for('host', user=current_user))
        elif table_name == 'conversion':
            return redirect(url_for('conversion', user=current_user))


@app.route('/configure', methods=['GET'])
def configure():
    socks_ip = request.args.get('ip')
    socks_port = request.args.get('port')
    socks_user = request.args.get('user')
    socks_pass = request.args.get('pass')

    # Check for required parameters
    if not (socks_ip and socks_port):
        return jsonify({"error": "Missing required parameters"}), 400

    # Get the IP address of the requested interface
    proxy_ip = request.remote_addr
    # Obtain proxy information based on the IP address of the requested interface
    proxy_url = alone_proxy_url(proxy_ip)

    if not proxy_url:
        return jsonify({"error": "Proxy not bind lan ip address"}), 404

    # Generate a configuration file with port number commands
    proxy_port = int(proxy_url.split(':')[-1])

    # Create the configuration based on the presence of user and pass
    if socks_user and socks_pass:
        config = alone_socks_config(proxy_port, socks_ip, socks_port, socks_user, socks_pass)
    else:
        config = alone_noauth_socks_config(proxy_port, socks_ip, socks_port)

    result = alone_running_socks(proxy_port, config)

    if result:
        return jsonify({"success": f"{proxy_ip} proxy and process started for port {proxy_port}"}), 200
    else:
        return jsonify({"failure": f"{proxy_ip} proxy and process started for port {proxy_port}"}), 200


if __name__ == '__main__':
    # app.run(port=80, host="0.0.0.0")
    # 启动获取系统数据的线程
    data_thread = threading.Thread(target=get_system_data)
    data_thread.start()
    # # 恢复运行的中转和路由规则
    # restore_system_state()
    # 启动服务
    socketio.run(app, port=80, host="0.0.0.0", allow_unsafe_werkzeug=True)
    # socketio.run(app, port=8000, host="localhost")
