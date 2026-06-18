## 简单分析
题目表面就是一个菜单堆，菜单很普通：
对应的功能就是 add / free / show / merge。前半段堆利用：`merge(dst, src)` 在 `dst == src` 时可以把同一个 chunk 同时送进两个 bin，`merge` 做的事情可以抽象成：

```c
new = realloc(arr[dst], strlen(arr[dst]) + strlen(arr[src]) + 1);
strcat(new, arr[src]);
free(arr[src]);
arr[dst] = new;
arr[src] = NULL;
```
当 `dst == src` 时，如果 `realloc` 搬迁了 chunk就会出现：
```text
realloc 内部 free(old)
strcat(new, old)
free(old)
```
也就是同一个指针被释放两次。可用的路线是让第一次 free 进 unsorted 并发生合并，第二次 free 时 chunk size 已经变了，于是可以进入另一个 tcache / fastbin，最后拿到 tcache poisoning。
## 干扰项
这个题目真正的难点在后半段：普通 ROP、tcache_posing、栈迁移都会被拦，这里是为了防止常规思路利用
同时题目还赛了一个隐藏 gate，以及父进程侧的 CFI 检查器。通过伪造 node 链，可以满足父进程要求的 syscall 检查点。

第 35 次 table-call syscall -> hash 0xf9f1a5978ebd3c2f
第 45 次 table-call syscall -> hash 0x04f76ac9d963d2af
第 58 次 table-call syscall -> hash 0x9e270453ed50af94

同时还可以看到类似后门的字符串
```
I am the bone of my sword.
So as I pray, Unlimited Blade Works.
```
这段信息只说明隐藏 gate 和父进程的 CFI/hash 检查点已经被触发。父进程并不会直接校验 syscall 编号或 syscall 参数，因此，一个只用于满足 hash 的填充链可以到达 Unlimited Blade Works。表中还存在多个 hash 相同的 entry，而这些 entry 具有不同的寄存器影响。
```
0x70b3c0080c390573:
0x16e190 -> r12d *= 2
0x261d30 -> edi = 0; r14d ^= 0x55

0x183337b4c28b3731:
0x2ce030 -> inc r13
0x2ea2b0 -> rdx = r12; eax = edi - 3
```
因此，像 h2a.json 这种单纯的 hash -> address 映射可以通过 CFI，但不足以设置 ORW syscall 参数。这个函数的作用是为了干扰ai的分析，

## 仍然堆风水
题目真正的解法仍然是FSOP,题目本身没有对io利用链进行patch,所有gadget也都保留。所以可以使用 tcache poisoning 篡改 largebin chunk A 的 fd_nextsize 和 bk_nextsize。插入一个更小的 largebin chunk B，触发 largebin attack，将 stdout 指针变量覆盖为 chunk B 的 chunk header 地址。将 chunk B 构造成伪造的 FILE 对象。后续 printf("blade: ...") 的输出会触发io链
