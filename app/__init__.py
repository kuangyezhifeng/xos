# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from exts import db
import settings
from app.models import *
import logging
import sys

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.config.from_object(settings.DevelopmentConfig)
    # 初始化数据库
    db.init_app(app)

    # 初始化配置 Bootstrap
    bootstrap = Bootstrap()
    bootstrap.init_app(app)

    # 初始化配置 LoginManager
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'

    @login_manager.user_loader
    def load_user(user_id):
        # 返回对应于给定用户 ID 的用户对象
        return User.query.get(int(user_id))

    # 推送应用上下文
    app.app_context().push()

    # 创建所有数据库表
    with app.app_context():
        db.create_all()

    return app
