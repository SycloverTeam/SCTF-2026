# Zombie_progression

该题目是QYQSの奇妙冒险系列的一部分（有看过极客大挑战的朋友应该会有印象喵），提升难度后放到了这里。之所以取这个名字是因为测题的时候有bro尝试爆破结果子进程开太多卡死了（bushi）. 该题目设计之初是想考察多进程时不易动态调试，以及一篇很屎的z3论文，但是放题前了解到其他RE师傅题目较难，于是将其进行了一些修改（三步检验一次），就跳过了剪枝优化的考点，没想到有师傅将其当作黑盒直接打了。Orz。

为了方便叙述，以下内容会用到一些程序源码中的变量名字，有空我会将源码整理好发布到我的博客中

程序整体主流程如下：

1. 初始化运行时 `cube_runtime_boot(...)`
2. 打印初始化后的 6x6 魔方可见状态
3. 从 stdin 读取一行用户输入的 move sequence
4. 解析并执行这些魔方转动
5. 如果隐藏校验通过，打印 flag
6. 否则打印变换后的魔方并输出：

```
Cube looks unstable.
```

大部分AI审计时会由于不会全量审计伪代码，所以第一步会直接尝试解这个6*6的魔方，导致浪费了一些时间，实际上，为了保证正确路径唯一，这里嵌入了一个隐藏状态，依赖了IPC轨迹，fd,TLS等相关信息组合成了解密flag的材料

输入支持如下：

- 面：`U D F B L R`
- 整体旋转：`x y z`
- 前缀层数：`2` 或 `3`
- wide move：`w`
- 后缀：`'` 或 `2`

一些限制：

- token 长度最大 5
- `x/y/z` 不能带 `w`
- prefix 不能用于整体旋转
- 宽度只支持 2 或 3
- parser 层最大支持 `CUBE_MAX_MOVES = 512`
- 但生成常量中真正期望的是 `GENERATED_COMMITMENT_COUNT = 36`，也就是最终校验期望 36 步

注意：由于解析时读取的字符串，所以得到相同结果的操作会导致不同的hash.

魔方的移动使用的是固定的sticker几何位置

```
x, y, z, nx, ny, nz
```

坐标范围是 `0..5`。旋转时程序会：

1. 判断 sticker 是否在本次转动层内
2. 将坐标映射到中心化坐标，例如 `-5, -3, -1, 1, 3, 5`
3. 围绕 X/Y/Z 轴旋转坐标和法向量
4. 计算目标 sticker cell
5. 移动 token



程序初始化时会解密一组generated token

每个 sticker token 20 字节：

```
visible_color
orientation
generation
hidden_secret
capability_seed
```

共 216 个 sticker

解密材料来自：

- 固定 session nonce
- label 字符串
- `GENERATED_SCRAMBLE_TEXT`
- commitment count

其中GENERATED_SCRAMBLE_TEXT是一个空字符串

而为了增大动态调试难度，我这里构造了大量的Linux IPC和线程结构，会在启动时fork很多子程序

face workers*6   每个魔方面一个进程

line workers*72  每个面6行+6列

slice workers*18   x/y/z各6层

broker*1  fd所有权和scm传递

watchdog*1  生成噪声

validator*1  校验和解密

而每个 face worker 内部还会启动大量线程：

- 36 个 sticker pthread
- 1 个 dispatcher pthread
- 1 个 tx-manager pthread
- 4 个 anchor clone task

而这里用到的共享内存结构里面包含：

- shared header
- registry entries
- fd owner metadata
- audit ring
- staging slots
- decoy region

通过`mprotect` 根据 phase 改变共享内存页权限，例如 staging 阶段开放写入，审计阶段开放 audit 写入。

而对于对每一步 move，大致流程是：

1. 增加 epoch
2. 设置共享状态为 `OP_ROTATE_PREPARE`
3. slice workers 处理 slice 轨迹
4. line workers 协调 face worker 执行行/列事务
5. watchdog 生成噪声 digest
6. 主进程更新可见魔方状态
7. broker 重新绑定 fd owner 信息
8. hidden runtime 更新隐藏 digest
9. validator 校验本步 audit
10. 更新共享 header 中的隐藏状态 hint

每个 sticker 线程维护自己的 TLS 状态：

```
__thread position_hash
__thread token_secret
__thread capability_seed
__thread visible_color
__thread orientation
__thread generation
```

一次 line transaction 大致分两阶段：

### PREPARE

face worker 通知 6 个 sticker 线程：

- 当前 epoch
- line slot
- move code
- fd digest
- tx id
- source staging slot

sticker 线程会把自己的 token 写入 shared staging slot，并生成 ack tag。

程序不是直接比较输入字符串，而是维护一系列 digest：

```
parser_digest
visible_digest
hidden_digest
orientation_digest
fd_digest
audit_root
path_digest
capability_chain
step_trace_digest
distributed_route_digest
distributed_tls_mesh_digest
anchor_digest
```

validator 每一步都会更新：

- capability chain
- step proof
- sparse checkpoint
- audit root
- path digest
- anchor digest
- poison 状态

最终 `OP_FINALIZE` 时检查：

- move count 是否等于 target
- parser digest 是否匹配
- step trace digest 是否匹配
- distributed route digest 是否匹配
- distributed TLS mesh digest 是否匹配
- finalize capability 是否匹配
- peer credential 是否正常
- sparse checkpoints 是否全部通过
- poison 是否为 0

如果全部满足，才会派生最终 key：

```
cube_derive_final_key(...)
```

然后用 ChaCha20 解密：

```
GENERATED_ENCRYPTED_FLAG[39]
```

解密后还会验证 plaintext 格式：

```
SCTF{...}
```

除了初始 token，还有一组运行期 target：

```
GENERATED_RUNTIME_TARGETS_ENC[144]
```

它会用 fd/tls/shm share hint 派生 key 后解密，得到：

- checkpoint stride
- checkpoint count
- expected parser digest
- expected step trace digest
- expected distributed route digest
- expected distributed TLS mesh digest
- expected move count
- expected commitment count

（原本这里是不会给expected的，由于117^36次方爆破不现实，这里会考察z3的高阶使用，由于这里最后没有使用就不提那个构式论文了）

---

在sub_62c0中我们可以看到

```
  v15[7] = __readfsqword(0x28u);
  a1[1580] = -1LL;
  if ( !(unsigned __int8)sub_D3C0(fds: &fds) )
    return 0;
  v2 = sub_8850(a1[2324] ^ 0x56414C494441544FLL, 0x52554E54494D4501LL);
  v3 = fork();
  v4 = v3;
  if ( v3 < 0 )
  {
    close(fd: fds);
    close(fd: fd);
    return 0;
  }
  if ( !v3 )
  {
    close(fd: fds);
    sub_42D0(fd: fd, v2, a1[2324], a1 + 1514);
  }
  close(fd: fd);
  fds_1 = fds;
  a1[1581] = v2;
  v6 = a1[2324];
```

子进程close  fd后会进入loop(42D0)

42D0较大，但是可以从留下的比较入手，在86B0

```
bool __fastcall sub_86B0(_BYTE *dst, unsigned __int64 n39)
{
  bool result; // al
  __int64 v3; // rcx

  result = n39 <= 6 || dst == 0LL;
  if ( result )
    return 0;
  if ( *(_DWORD *)dst == 'FTCS' && dst[4] == 123 && dst[n39 - 1] == 125 )
  {
    v3 = 0LL;
    while ( (unsigned __int8)(dst[v3] - 32) <= 0x5Eu )
    {
      if ( ++v3 >= n39 )
        return 1;
    }
  }
  return result;
}
```

这里会比较前缀是否为SCTF

通过交叉引用可以看到

```
          optval[5] = _mm_unpackhi_epi64(v53, v55);
          optval[6] = v57;
          optval[7] = v52;
          v261 = *(_QWORD *)&buf_1[11];
          sub_85C0(optval: optval, buf: buf_7);
          sub_8F50(dst: dst, n39: 0x27uLL, buf: (char *)buf, CubeIPC6_dev: "CubeIPC6-dev", a5: 0, a6: v59);
          v60 = sub_86B0(dst: dst, n39: 0x27uLL);
          buf = buf_3;
          memset(buf: &buf_3[2], value: 0, count: 0x2BuLL);
          LOBYTE(v244) = v60;
```

85c0和8f50就是生成key流以及解密的过程

而为了降低难度，这里使用了每3步比较一次

```
              v160 = sub_8850(v158, v244);
              n = sub_8850(v160, n);
              if ( !BYTE8(buf_1[21])
                || __PAIR64__(buf_1[0], DWORD1(buf_1[0])) != *(_QWORD *)((char *)&buf_1[20] + 4)
                || *(_OWORD *)((char *)buf_1 + 8) != buf_1[17]
                || *(_OWORD *)((char *)&buf_1[1] + 8) != __PAIR128__(n, *(unsigned __int64 *)&buf_1[18])
                || *((_QWORD *)&buf_1[2] + 1) != v244 )
              {
                *(_QWORD *)&buf_1[11] = sub_8850(*(_QWORD *)&buf_1[11] ^ 0x43415053554C452DLL, v244 ^ DWORD2(buf_1[20]));
              }
```

所以定位到这里后，就可以patch程序，爆破这3步就行

这里的实现方法很多，可以hook send函数，patch一段新指令打印出来。

在设计时为了减轻patch难度，在回复包中我预留了一个8字节的位置（5c8e）

```
.text:0000000000005C8E                 mov     [rsp+478h+var_232], rax
```

所以可以将想看的值写到这里带出即可

需要注意的是，第一个block是可以静态获取的，而第11个时没有下一个，需要一点小小的爆破。