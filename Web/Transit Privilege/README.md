## 标题

Transit Privilege

### 作者

lhRaMk7

### 方向

web

### 知识点

- WebSocket 自定义协议分析
- 固定密钥 HMAC 签名恢复
- 协商型能力绑定 `cap.sync`
- workspace facade / actionId 工作流分析
- reviewer 隐式污染导致的业务提权
- 管理员支持包泄露服务端 jar
- Java 原生反序列化
- `char -> byte` 低 8 位截断 / Ghost Bits 风格路径物化
- 受限文件读取链中的路径逃逸

### 难度

高级

### 内容

一个运维平台题目。公网只有普通 Web 控制台和 `/proxy` WebSocket 转发入口。选手先从附件 `player.jar` 中恢复协议与签名规则，利用 `cap.sync` 创建一个可登录后台的 `OPERATOR` 用户；登录后通过 workspace facade 的 routing 逻辑污染审批人，把自己升到 `ADMIN`；随后借管理员支持包拿到服务端 jar，分析 `/admin/maintenance/reconcile` 的反序列化入口与 `ProbeSandbox` 中的低字节路径物化，最终读取 `/flag`。

为了适配静态共享环境，账号密码必须至少 8 位并同时包含字母和数字；用户之间的审批记录和 maintenance report 都按账号隔离，不能直接复用别人的过程或结果。

### 提示

- 无


### FLAG

当前 Dockerfile 演示 flag：

- `SCTF{Tr4ns1t_Pr0b3_4107_M@sTer}`

正式部署时建议由平台写入 `/flag`，不要把正式 flag 固化在镜像里。

### 是否可共享

否

### 备注

- 选手附件建议只提供 `attachments/edge-agent-client-0.1.0.jar` 和远程实例。
- 不要把 `README.md`、`writeup/`、`exp/`、`sourcecode/` 一起下发给选手。
- 如果发放管理员支持包，保持 zip 内只有单个服务端 jar，避免无关文件干扰利用链。
