---
noteId: "17f231f07c3711f19edf53c6950af6aa"
tags: []

---

# ghost_projection

## 方向

逆向

## 知识点

- Linux ELF 逆向
- Stripped PIE 分析
- 多阶段 Loader / 内存映射 ELF
- 真假路径与 Decoy Check 分离
- 全局状态结构体恢复
- 控制流与数据流还原
- 动态调试 / Trace / 中间状态提取
- Hidden Oracle / Gate 条件分析

## 难度

中等

## 内容

路径从来不只是一条路径。

有些脚步是真实的，有些只是回声，有些则因为你注视它们才存在。  
投影记住了太多不该记住的东西，但只有当正确的门被打开时，它才会开口。

你能找到穿过深渊的路线吗？

A path is never just a path.

Some steps are real, some are echoes, and some only exist because you looked at them.  
The projection remembers more than it should, but it will not speak unless the right gates are opened.

Can you find the route through the abyss?

## 提示

- 不要急着相信每一条检查路径，先区分真实路径和回声路径。
- 注意 Loader 解出的真实执行体，以及运行时被重建出来的全局状态。
- projection 相关逻辑里有一组 gate；门打开前，它看起来只是在制造噪声。
- 有些信息不会直接打印出来，但可以在正确的位置被观察到。

## 运行

```bash
cd src/player
chmod +x ghost_abyss_hardened
./ghost_abyss_hardened
```

## Docker

```bash
cd src/player
docker build -t ghost_projection .
docker run --rm -it ghost_projection
```
