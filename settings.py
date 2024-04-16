# -*- coding: utf-8 -*-
import os

class Config:
    # MYSQL数据库配置信息
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:sbitxumtdh@127.0.0.1:3306/route'
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLALCHEMY_ENGINE_OPTIONS = {'pool_recycle': 1, 'pool_size': 20}
    # SQLALCHEMY_ECHO = True
    # # SQLITE3配置
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app', 'xos.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    # secret_key session机制
    SECRET_KEY = 'sbitxumtdh1988919'
    # 项目路径
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    # 静态文件夹路径
    STATIC_DIR = os.path.join(BASE_DIR, 'static')
    TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')




class DevelopmentConfig(Config):
    ENV = 'development'
    DEBUG = True


class ProductionConfig(Config):
    ENV = 'production'
    DEBUG = False
