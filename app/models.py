# -*- coding: utf-8 -*-
# ORM 类 ----------》表
# 类对像 ----------》 表中的一条记录
from datetime import datetime
from flask_login import UserMixin
from exts import db
from werkzeug.security import generate_password_hash, check_password_hash
'''
常用类型
db.Integer    int
db.String(15) varchar(15）
db.Datetime   datetime
'''

# 创建了一个ORM模型，模型就是类，必须继承db.Model
class User(UserMixin, db.Model):  # 创建了user表
    # db.Column(类型,约束)映射表的中列
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)  # 用户名
    email = db.Column(db.String(255), nullable=False)     # 邮箱
    password_hash = db.Column(db.String(255), nullable=False)  # 密码哈希
    is_active = db.Column(db.Boolean, default=True)
    # 添加密码设置和验证方法
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class ProxyDevice(db.Model):
    __tablename__ = 'proxy_devices'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    proxy_url = db.Column(db.String(length=760), nullable=False, unique=True)
    access_ip = db.Column(db.String(length=255))
    node_ip = db.Column(db.String(length=255))
    country = db.Column(db.String(length=15))
    protocol = db.Column(db.String(length=15))
    status = db.Column(db.String(length=15))
    device_ip = db.Column(db.String(length=65535))
    tag = db.Column(db.String(length=15))
    flag = db.Column(db.Integer)
    note = db.Column(db.String(length=255))
    gateway = db.Column(db.Integer)
    # note = db.Column(db.String(length=255,collation='utf8mb4_bin'))


class RelayConnection(db.Model):
    __tablename__ = 'relay_connections'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    protocol = db.Column(db.String(length=15), nullable=False)
    source_port = db.Column(db.Integer, nullable=False)
    target_ip = db.Column(db.String(length=15), nullable=False)
    target_port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(length=15))
    tag = db.Column(db.String(length=15))
    note = db.Column(db.Text)


class Host(db.Model):
    __tablename__ = 'host'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(15))
    country = db.Column(db.String(length=255))
    day = db.Column(db.Date, default=datetime.now)
    ip = db.Column(db.String(15), unique=True, nullable=False)
    account = db.Column(db.String(256), nullable=False)
    password = db.Column(db.String(256), nullable=False)  # 明文存储密码
    port = db.Column(db.Integer, nullable=False)
    website = db.Column(db.String(256))
    remark = db.Column(db.String(256))
    active = db.Column(db.String(15))
    

class Host_Config(db.Model):
    __tablename__ = 'host_config'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(15))
    main_ip = db.Column(db.String(15), nullable=False)
    auxiliary_ip = db.Column(db.String(15), nullable=False)
    protocol = db.Column(db.String(10))
    speed_limit = db.Column(db.Integer)
    proxy_url = db.Column(db.String(760))
    created_at = db.Column(db.Date, default=datetime.now, nullable=False)
    expiration_date = db.Column(db.Date)
    status = db.Column(db.String(10))
    remark = db.Column(db.String(256))


class Conver(db.Model):
    __tablename__ = 'conver'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    proxy_ip = db.Column(db.String(255))
    real_ip = db.Column(db.String(255))
    country = db.Column(db.String(255))
    city = db.Column(db.String(255))
    inbound_protocol = db.Column(db.String(10))
    inbound_connections = db.Column(db.Text)
    outbound_protocol = db.Column(db.String(10))
    outbound_connections = db.Column(db.Text)
    tag = db.Column(db.String(length=15))
    status = db.Column(db.String(255))
    flag = db.Column(db.Integer)