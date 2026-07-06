## 标题

ParcelBridge Vault

### 作者

Arahat0

### 方向

pwn / android

### 知识点

- exported Activity 与显式 Intent 调用
- Parcelable / Parcel 字段顺序差异
- Bundle ClassLoader 与自定义 Parcelable 反序列化
- WebView addJavascriptInterface 暴露面分析
- 本地 HTTP payload 与 JSBridge 回传

### 难度

高级

### 内容

这个APK好像有点漏洞

### 提示

- 目标 APK 的跨组件数据传递并不只依赖普通字符串 extra。
- WebView 侧的桥对象需要满足前置会话状态后才会导出数据。

### FLAG

静态 flag

### 是否可共享

否

### 备注

本题为服务端 Android 模拟器环境题。每次提交独占一个预热 slot；提交结束、失败或超时后，对应容器都会销毁并重建。单个 IP 同时只保留一个活跃任务，新提交会替换旧任务。

选手最终提交完整 `SCTF{...}` 格式 flag。
