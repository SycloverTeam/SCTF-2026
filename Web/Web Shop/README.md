## 标题
Web Shop

### 作者
ivory

### 方向
Web

### 知识点

- LangChain metadata 反序列化
- 环境变量 secret 泄露
- HMAC 票据伪造
- Python 沙箱逃逸
- `str.format` 字段访问绕过静态检测
- 生成器 frame locals 读取

### 难度

中级

### 内容

一个在线 Web Shop。选手需要通过商店、聊天区和客服 Bot 逐步获取后台权限，最终利用规则测试台中的 Python 沙箱缺陷读取发货预览中的 flag。

### 提示

- 商店里可下载的客服调试脚本说明了客服登录票据的签发方式。
- 聊天 metadata 的恢复逻辑与 LangChain 序列化对象有关。

### FLAG

`SCTF{human_cas3_the_m@in_pr0blem_not_bot}`

### 是否可共享

是

###  备注

环境题，无选手附件。服务监听容器内 8080 端口，部署文件位于 `env/`，源码归档位于 `sourcecode/sourcecode.zip`，攻击脚本位于 `exp/exp.py`，题解位于 `writeup/writeup.md`。
