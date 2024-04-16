#!/bin/bash

# 停止之前的app
echo "Stopping previous app..."
screen -S XOS -X quit  # 假设你的screen会话名字为app_session

# 激活虚拟环境
echo "Activating virtual environment..."
source /usr/local/flask/bin/activate

# 启动新的app
echo "Starting the app..."
screen -dmS XOS python3 /usr/local/xos/app.py

echo "App started successfully."

