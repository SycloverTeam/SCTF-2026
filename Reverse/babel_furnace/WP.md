# babel_furnace

简单的crack me

该程序一共由几个部分组成：

- 主程序
- bridge.pyd
- engine.dll
- python_carrier.bin

我将其放在了/bin下用以参考

---

程序功能很简单

读取 stdin 中的 48 字节候选 flag，经过 Host + Python + Pyd + Rust Engine 四层拆分验证，正确则输出 `Correct.`，错误则输出 `Nope.`。

运行链路是

```
babel_furnace.exe
  -> C++ Host
  -> 手动映射 embedded Python 3.11.9
  -> 解出并映射 bridge.pyd
  -> 执行 marshaled Python bootstrap
  -> Python 调用 bridge.verify(ctx)
  -> bridge.pyd 解出并映射 engine.dll
  -> bridge 多次调用 engine_resume()
  -> Rust Engine 执行 80 个 VM block
  -> 最终 accepted == 1 则 Correct
```

验证逻辑不是集中在单个模块里，而是拆成四层：

| 层                | 作用                                                         |
| ----------------- | ------------------------------------------------------------ |
| Host / C++        | 读输入、恢复 fragment、映射 Python / bridge / engine，提供 host shares |
| Python            | 提供 `Context.oracle()`，从 carrier code object 中释放 Python share |
| bridge.pyd / C++  | 解 carrier、组合 input、调度 engine、传递 pyd shares         |
| engine.dll / Rust | 解密 VM page，组合 shares，执行 VM，判断最终结果             |

Host 主要实现了一个简化版 Windows PE loader：

- 校验 DOS/NT header
- `VirtualAlloc` 分配镜像
- 拷贝 section
- 应用 relocation
- 解析 import table
- 注册 exception table
- 执行 TLS callback
- 执行 DLL entry point
- 设置 section 权限
- 解析 export

并且内嵌了320个0x800的fragment

流程：

1. 从 start index 找到第一个 fragment
2. 用 bootstrap key 解密 fragment payload
3. 校验 tag
4. 通过 `next_encoded ^ mask` 找下一个 fragment
5. 每段解完后派生 next key
6. 直到 `FLAG_LAST`

Host 给 bridge.pyd 绑定了一组 API：

```
restore_component
release_component
get_edge_share
get_page_key_share
get_target_share
get_input_mask_share
get_immediate_shares
secure_wipe
```

也就是说 bridge 和 engine 缺 Host 这一层的 share 就不能完整恢复验证逻辑。

---

python层：

python share 被藏在 Python code object 的字段里：

| code object 字段    | 用途                                                        |
| ------------------- | ----------------------------------------------------------- |
| `co_exceptiontable` | 80 个 block 的 Python token / immediate，每块 128 字节      |
| `co_linetable`      | 16 个 page 的 Python page key share，每页 32 字节           |
| `co_name`           | 80 字节 block permutation                                   |
| `co_qualname`       | engine start/key share、input permutation share、input mask |

`oracle()` 还会把 `block_id`、`transcript`、`nonce` 混进 1024-bit 值，返回给 bridge。bridge 再拆成 16 个 `uint64_t`：

- 前 8 个作为 `python_token`
- 后 8 个作为 `python_immediate`

---

bridge.pyd:

`bridge.verify(ctx)` 做这些事：

1. 读取 `ctx.raw`，也就是用户输入
2. 检查长度必须是 48 字节
3. 解码 Python carrier
4. 用 Python/Pyd/Host 三方 input permutation 和 mask 构造 engine input words
5. 组合 engine bootstrap 信息
6. 通过 Host API 恢复 `engine.dll`
7. 手动映射 engine.dll
8. 获取导出函数：

```
engine_create
engine_resume
engine_destroy
```

1. 循环调用 `engine_resume`

bridge 调 engine 的循环最多 192 次，但实际 VM 是 80 个 block。Engine 每次不会一次性完成验证，而是返回状态码要求 bridge 补材料：

```
0x101 NEED_PAGE
0x102 NEED_BLOCK
0x103 EXECUTED_BLOCK
0x104 FINISHED
```

每个 packet 里会填入：

- input words
- Python tokens
- Python immediates
- Pyd operand tokens
- Pyd immediate masks
- Host immediate shares
- Python/Pyd/Host page shares
- Host/Pyd edge shares
- target shares
- packet tag

packet tag 用 `SplitMix64` 吸收这些字段生成，用来防止中途伪造材料。

---

Rust Engine:

VM 参数：

```
BLOCK_COUNT = 80
PAGE_COUNT = 16
BLOCKS_PER_PAGE = 5
BLOCK_OP_COUNT = 8
```

也就是：

```
80 blocks * 8 ops = 640 micro-ops
```

每 5 个 block 放进一个 encrypted page，共 16 页。

Engine 每次需要新 page 时，会向 bridge 请求 page shares。page key 由四方 share 组合：

```
engine_page_share
^ python_page_share
^ pyd_page_share
^ host_page_share
```

再经过 splitmix 派生 32 字节 page key。

page payload 用一个 FNV-1a 风格的 keystream XOR 加密。解密后还会校验 page tag。

每个 block 中，一条 micro-op 的真实 opcode / operand / immediate 都需要四层组合：

```
logical_opcode =
    engine_opcode_share
  ^ (pyd_token & 0x1F)
  ^ (python_token & 0x1F)

dst =
    ((pyd_token >> 5) & 0x0F)
  ^ (engine_operand_mask & 0x0F)

src_a =
    ((pyd_token >> 9) & 0x0F)
  ^ ((python_token >> 8) & 0x0F)

src_b =
    ((pyd_token >> 13) & 0x0F)
  ^ ((engine_operand_mask >> 4) & 0x0F)

immediate =
    python_immediate
  ^ pyd_immediate_mask
  ^ engine_immediate_mask
  ^ host_immediate
```

主要 opcode：

```
MOV
MOVI
XOR / XORI
ADD / ADDI
SUB
MUL
ROL
NIBBLE_SBOX
LOAD_INPUT
LOAD_KEY
PY_WINDOW
TRANSCRIPT
SWAP3
ASSERT_TAG
NOISE
HALT
```

生成的 640 条 micro-op 分布大致是：

```
MOV             222
ADD             112
XOR              84
ROL              84
LOAD_KEY         42
NIBBLE_SBOX      42
NOISE            18
TRANSCRIPT       15
LOAD_INPUT        6
XORI              6
ASSERT_TAG        6
PY_WINDOW         2
HALT              1
```

逻辑上，它验证的是一个 384-bit permutation：

```
6 * uint64 = 384 bits
```

核心参数：

```
ROUND_COUNT = 14
WORD_COUNT = 6
```

每轮大致流程：

1. 加 round key
2. XOR 邻接 word
3. ROL 旋转
4. nibble S-box 替换
5. 若干加法混合
6. word permutation

----

所以解法是：

合并 Python / Pyd / Engine 三方 round key share

合并 rotation share

合并 permutation share

合并/还原 target

对 target 做 `invert_transform`

得到原始 48 字节 flag