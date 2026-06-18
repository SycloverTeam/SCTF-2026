## 标题
CHAOS;HEAD
### 方向
pwn

### 知识点

- C++
- STL
- 事务系统对象生命周期
- 堆布局复用
- 信息泄漏
- 函数指针覆盖与 ROP

### 难度

中级

### 内容

内存里的字节像涩谷坏掉的霓虹一样闪烁。  
屏幕另一端传来的，不是消息，而是崩溃前的判错。  
我明明没有去看世界，世界却从 core dump 里回望着我。  
——那双眼睛，是谁的眼睛？

The bytes in memory flickered like Shibuya’s broken neon.  
What came from the other side of the screen was not a message, but an omen before the crash.  
I never went looking at the world, yet the world stared back at me from the core dump.  
—Whose eyes are those eyes?

### 提示

- 关注事务系统嵌套、容器扩容以及对象生命周期。
- `DUMP SNAPSHOT` 会通过 route 中的函数指针导出 snapshot。
