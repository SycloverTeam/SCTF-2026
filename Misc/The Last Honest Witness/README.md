## 标题
The Last Honest Witness

### 作者
0xWeakSheep

### 方向
Misc / Blockchain / Crypto

### 知识点

- Fermat 分解接近素数 RSA 模数
- RSA 私钥恢复与明文解密
- Merkle tree 成员路径构造
- Foundry / Anvil 链上交互

### 难度

高级

### 内容

一次链上安全事故后，委员会收到了 32 份匿名证词。每一份证词都被压进同一棵 Merkle Tree，见证人的真实身份被隐藏，只留下一个 commitment。为了防止伪造，委员会又将关键见证人的口供用 RSA 加密后公开。

系统不相信名字，不相信声明，也不关心谁先喊出答案。它只接受证明：你能还原被隐藏的事实，知道事实背后的身份因子，并能在不公开完整名单的情况下证明该匿名身份属于见证人集合。

选手连接题目服务后会获得独立 Anvil 实例、`Setup` 合约地址和私钥。选手需要从链上 storage/logs 取回主 RSA 参数和 Merkle root，恢复明文并构造 Merkle opening；同时解出 Franklin-Reiter RSA、secp256k1 小范围离散对数签名、Keccak 截断碰撞三个 fragment，调用 `claim` 清空 3 个 vault 中合计 `100 ether`。

### 提示

- The two guardians of the modulus were born almost at the same time.
- The witness does not reveal a name, only a commitment.
- The tree accepts only one active voice among many empty seats.

### FLAG

静态 flag：`SCTF{SYC_!ntern_Ray}`。

### 是否可共享

否

### 备注

选手最终提交完整 `SCTF{...}` 字符串。
