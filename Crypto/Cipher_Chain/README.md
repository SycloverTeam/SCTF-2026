## 标题
Curve_Link

### 作者
Lumi.

### 方向
Crypto

### 知识点

- 有限域 GF(65537) 运算；
- 校验矩阵与低重量码字；
- meet-in-the-middle 搜索；
- SHA256 计数器模式密钥流；
- 哈希迭代 KDF；
- 标准 X25519 协商；
- 摘要前缀校验；
- 字节流异或解密。

### 难度

初级

### 内容

附件给出 `task1.txt`、`task2.pub`、`task2.enc`、`task2.log`、`task2.trace`。

本题分为前后联动两阶段。Task1 的解密结果不是最终 flag，而是 Task2 的唯一 seed。若 Task1 seed 错误，Task2 的中间校验无法通过，也无法还原最终明文。

### 提示

- 校验矩阵只描述了 `h` 所在的空间，真正有用的限制藏在 `h` 本身：小重量、带符号、有限域。完整枚举不是不可行，而是需要换一种拆法。
- `task2.trace` 不是伪代码，而是工程侧记录。先判断 `burn_counter` 作用在曲线交换之前还是之后；`task2.log` 里的短串只用于确认你是否到达了正确的会话中间态。

### FLAG

SCTF{curve25519_bsuiahduie_cif_diqw}

### 是否可共享

否

###  备注

本题为纯附件题，无运行环境，无需部署 Docker。

