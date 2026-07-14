#!/bin/sh
set -eu

# GateCrash — Flag 注入脚本
# 平台通过此脚本将动态 Flag 写入容器
echo "$1" > /flag
