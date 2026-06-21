# The Last Honest Witness CTF

这是一个单题智能合约 CTF 环境。选手通过 `nc` 领取独立 Anvil 实例，解出 `06_last_honest_witness` 后回到 `nc` 领取 flag。

## 题目

| ID | 名称 | 类型 | 难度 | 分值 |
|----|------|------|------|------|
| `06_last_honest_witness` | The Last Honest Witness | Misc | Hard | 500 |

题目目标：恢复关键证词，生成满足 Poseidon Merkle 成员校验的 Groth16 proof，并清空挑战合约中的 `100 ether`。

服务端不会直接暴露 Anvil 开发 RPC。选手拿到的是过滤后的 JSON-RPC 代理，只允许正常链上读写方法和签名交易广播，`anvil_*`、`hardhat_*`、`evm_*`、`debug_*` 以及 `eth_sendTransaction` 均被禁用。

选手材料位于：

- `challenges/06_last_honest_witness/src/Challenge.sol`
- `challenges/06_last_honest_witness/src/Groth16Verifier.sol`
- `challenges/06_last_honest_witness/handout/README.md`
- `challenges/06_last_honest_witness/handout/merkle_helper.py`
- `challenges/06_last_honest_witness/handout/poseidon_helper.js`
- `challenges/06_last_honest_witness/handout/package.json`
- `challenges/06_last_honest_witness/handout/zk/`

## 目录结构

```text
ctf/
├── challenges/
│   └── 06_last_honest_witness/
│       ├── challenge.json
│       ├── foundry.toml
│       ├── handout/
│       │   ├── README.md
│       │   ├── merkle_helper.py
│       │   ├── package.json
│       │   ├── poseidon_helper.js
│       │   └── zk/
│       └── src/
│           ├── Challenge.sol
│           ├── Groth16Verifier.sol
│           └── Setup.sol
├── server/
│   ├── app.py
│   ├── instance_manager.py
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

## 启动

### Docker

```bash
cd ctf
export PUBLIC_HOST="127.0.0.1"
docker-compose up --build
```

远程部署时，把 `PUBLIC_HOST` 设置为服务器公网 IP 或域名。

### 本地开发

```bash
cd ctf
pip install -r server/requirements.txt
FOUNDRY_BIN="$HOME/.foundry/bin" python server/app.py
```

## 选手流程

连接题目服务器：

```bash
nc <host> 1337
```

菜单中选择：

```text
[1] List challenges
[2] Launch new instance
[3] Get flag
[4] Kill instance
[0] Exit
```

启动实例时输入：

```text
Challenge ID > 06_last_honest_witness
Player name  > alice
```

服务端会返回：

```text
export RPC=http://<host>:20xxx
export PK=<player-private-key>
export SETUP=<setup-address>
```

查询挑战合约地址：

```bash
export CHALLENGE=$(cast call "$SETUP" "challenge()(address)" --rpc-url "$RPC")
```

解题后调用 `claim(...)`，再回到 `nc` 菜单选择 `3` 领取 flag。

## 验证

编译题目：

```bash
forge build --root challenges/06_last_honest_witness
```

检查服务器 Python 文件：

```bash
python -m py_compile server/app.py server/instance_manager.py
```

## 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PUBLIC_HOST` | `127.0.0.1` | 返回给选手的 RPC 主机名 |
| `INSTANCE_TIMEOUT` | `1800` | 实例自动销毁时间，单位秒 |
| `PORT` | `1337` | nc 服务器监听端口 |
| `ANVIL_PORT_MIN` | `20000` | 选手 RPC 代理端口范围起点 |
| `ANVIL_PORT_MAX` | `20200` | 选手 RPC 代理端口范围终点 |

题目使用静态 flag：`SCTF{SYC_!ntern_Ray}`。
