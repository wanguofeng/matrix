#!/bin/bash

# 定义应用程序名称和路径
APP_NAME="btsensor"
APP_PATH="/home/guofeng/Workspace/myself/matrix/matrix/external/bluez/bluez-5.65/peripheral"

while true; do
  # 随机生成一个1到5之间的整数，表示等待的秒数
  WAIT_TIME=$(( (RANDOM % 40) + 30 ))

  echo "Waiting $WAIT_TIME seconds before restarting $APP_NAME"

  # 等待一段时间
  sleep $WAIT_TIME

  # 检查应用程序是否已经运行
  if pgrep $APP_NAME > /dev/null; then
    # 关闭应用程序
    pkill $APP_NAME

    echo "$APP_NAME has been killed. Restarting..."

    # 启动应用程序
    $sudo $APP_PATH/$APP_NAME &
  else
    echo "$APP_NAME is not running. Starting..."

    # 启动应用程序
    $sudo $APP_PATH/$APP_NAME &
  fi
done

