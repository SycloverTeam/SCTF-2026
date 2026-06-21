# 部署说明

## 构建

```bash
docker build -t last_honest_witness:latest .
```

## 运行

```bash
docker run -itd \
  -p 1337:1337 \
  -p 20000-20200:20000-20200 \
  --name last_honest_witness \
  last_honest_witness:latest
```

选手连接：

```bash
nc <host> 1337
```

容器只向选手暴露过滤后的 JSON-RPC 代理端口。内部 Anvil 仅绑定 `127.0.0.1`，开发 RPC 方法不会暴露给选手。

如需远程返回公网 RPC 地址，运行容器时设置：

```bash
-e PUBLIC_HOST=<public-ip-or-domain>
```
