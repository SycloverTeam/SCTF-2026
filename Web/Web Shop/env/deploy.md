# Web Shop 部署说明

## 构建

```bash
docker build -t web-shop:latest .
```

## 运行

平台只需执行最基本的 `docker run -itd` 即可启动容器；服务监听容器内 `8080` 端口。

本地测试示例：

```bash
docker run --rm -p 8080:8080 \
  -e FLAG='SCTF{test_flag}' \
  web-shop:latest
```

访问：

```text
http://127.0.0.1:8080
```

## Flag

- Web 题 flag 路径使用 `/flag`。
- 服务启动时会读取 `FLAG` 环境变量写入 `/flag`；平台后续也可以用 `script/pushflag.sh` 直接覆盖 `/flag`。
- 题目内部的发货预览读取路径由 `FLAG_PATH=/flag` 固定到 `/flag`。
- `SHOP_SUPPORT_SEED` 已在镜像环境中设置，平台不需要额外传入环境变量。

## 进程

`start.sh` 后台启动 uvicorn，并用 `tail -f /dev/null` 保持容器存活，符合归档要求中“赛题服务进程不作为主进程”的约束。
