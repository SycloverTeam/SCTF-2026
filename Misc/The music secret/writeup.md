# The music secret

## Description

The music platform discovered inconsistencies between the music in its edge cache and the studio archives, and conducted packet capture analysis.

## Author

lhRaMk7

## solutions


这题给的核心附件只有一个抓包文件：

```text
stream.pcapng
```

表面看像流量题，但真正做下来，它其实是三层信息叠在一起：

1. 流量层给出恢复方式和关键约束；
2. 音频层提供真正承载数据的差分信号；
3. framing 和纠错层负责把这些差分信号还原成稳定的数据流。

所以这题不是去“听音频”或者盲目跑字符串，而是先把流量里的提示吃干净，再按这些提示去恢复音频、同步字、帧结构和最后的编码内容。

完整链路可以概括成：

```text
PCAPNG
-> 重组两路 HTTP Range 音频
-> 从 cache 请求顺序派生密钥
-> 比较 studio / cache 两路 WAV 的采样差
-> 恢复编码周期
-> 提取同步字和数据帧
-> 做 Hamming(7,4) 纠错和 CRC16 校验
-> XOR 后得到 base64
-> base64 解码得到 flag
```

---

## 一、先看抓包里到底给了什么

用 Wireshark 打开 `stream.pcapng`，最先值得看的就是 HTTP 流量。  

很快能看到几条比较关键的请求：

- `/api/v1/incidents/INC-2407`
- `/api/v1/playback/session?track=7`
- `/edge/v1/assets/7/studio`
- `/edge/v1/assets/7/cache`
- `/api/v1/diagnostics/export`

其中前两个最重要。

### 1. incident 回包在提醒“抓包不完整”

`/api/v1/incidents/INC-2407` 返回：

```json
{
  "incident": "INC-2407",
  "track_id": 7,
  "alert": "edge cache checksum differs from studio archive",
  "capture": "sensor started late; spool quota stopped collection early",
  "recovery": "client range retries may cover truncated responses"
}
```

这段其实已经把做题方向交代得很明显了：

1. 抓包开始得晚；
2. 抓包结束得早；
3. 会有响应被截断；
4. 如果想把资源恢复出来，不能只看单个响应，要利用后续的 Range 重试去补。

### 2. playback session 给出了节奏和帧结构

`/api/v1/playback/session?track=7` 的返回里有这样几项：

```json
{
  "title": "Stream of Sound",
  "stream": "HTTP Range",
  "hint": "the rhythm remembers; order opens the cache",
  "bpm": 120,
  "subdivision": 2,
  "frame_sync_symbols": 8,
  "frame_fields": ["index", "length"],
  "frame_checksum": "crc16",
  "frame_order": "indexed"
}
```

这几个字段后面都会用到：

- `bpm = 120`
- `subdivision = 2`
- `frame_sync_symbols = 8`
- `frame_fields = ["index", "length"]`
- `frame_checksum = "crc16"`
- `frame_order = "indexed"`

另外，响应头里也有配套提示：

```text
X-Key-Schedule: sha256(agent|id|csv(first-seen-range-start))
X-Stream-FEC: hamming-7-4
X-Frame-Sync: 8-symbol
X-Frame-Fields: index,length
X-Frame-Check: crc16
X-Frame-Order: indexed-blocks
X-Capture-State: late-start,quota-stop
```

到这里其实已经能定下来几件事：

- key 不在音频正文里，而是跟请求顺序有关；
- 数据流里有 Hamming(7,4)；
- 帧有同步字；
- 帧顺序需要靠 `index` 重组；
- `crc16` 是最终判断对不对的重要依据。

---

## 二、为什么第一步是重组 WAV，而不是直接听

题目里真正的两路资源是：

- `/edge/v1/assets/7/studio`
- `/edge/v1/assets/7/cache`

这两个资源都不是整文件下载，而是反复使用：

```http
Range: bytes=start-end
```

服务端返回的是：

```http
206 Partial Content
Content-Range: bytes start-end/total
```

所以这里第一反应不能是把包体顺着拼起来，而是要按 `Content-Range` 指定的位置去回填。

实际检查后，也确实能看到不完整对象，例如：

```text
/edge/v1/assets/7/studio      2600 / 16384 bytes
/edge/v1/assets/7/cache       2600 / 16384 bytes
/api/v1/diagnostics/export    1900 / 65576 bytes
```

这就说明如果粗暴地按抓包顺序拼文件，音频一定会坏。

正确做法是：

- 请求要保留，因为后面还要用来派生 key；
- 不完整响应不能直接当最终数据；
- 需要用后面重叠或补发的 Range 去把缺口补齐。

按这个方式重组后，可以恢复出两份完整 WAV：

- `studio.wav`
- `edge-cache.wav`

而且两者参数一致：

```text
mono IEEE float32 WAV
8000 Hz
```

这个前提很重要，因为后面所有差分恢复都建立在“采样逐点对齐”上。

---

## 三、先把 key 从流量里拿出来

题目没有把 key 直接塞进文件里，而是放在响应头提示中：

```text
sha256(agent|id|csv(first-seen-range-start))
```

这三部分分别对应：

- `agent`：User-Agent
- `id`：track id
- `csv(first-seen-range-start)`：cache 这一路里，每个 Range 起始偏移第一次出现时的顺序

这里最容易做错的是最后一项。  

不是按偏移大小排序，也不是把所有重复的起点都算进去，而是：

1. 只看 `/edge/v1/assets/7/cache`
2. 按抓包里的实际先后顺序扫描请求
3. 从 `Range: bytes=start-end` 里取 `start`
4. 同一个 `start` 只保留第一次

当前这份附件里，可以提取到：

```text
280 个唯一 start
```

前 10 个值是：

```text
3194880, 2686976, 3817472, 3932160, 1948160,
2244608, 1277952, 3096576, 1359872, 1949696
```

把材料拼成：

```text
StreamClient/2.1|7|3194880,2686976,3817472,...
```

再做 SHA-256，就能得到后面 XOR 所需的 key。  

题目里这个 key 的前 8 字节是：

```text
a679df158ff5d930
```

这个值很适合作为中间检查点：如果这里就算错了，后面音频部分即使看起来有点像，也不用继续浪费时间。

---

## 四、为什么编码周期是 2000 个采样点

这个地方不是靠猜，而是题目已经把约束给够了。

session 元数据里给出：

- `bpm = 120`
- `subdivision = 2`

换算一下：

- 120 BPM = 每秒 2 拍
- subdivision 2 = 每拍 2 个子单位

也就是每秒 4 个符号。

而 WAV 采样率是：

```text
8000 Hz
```

所以每个符号对应：

```text
8000 / 4 = 2000 samples
```

后面再去看两路音频的差分，也能验证这一点：强差异会稳定落在 2000-sample 的网格上。

---

## 五、真正承载数据的是 `studio` 和 `cache` 的差分

单独看任意一路音频，都不太像在直接藏东西。  

真正有用的是把 `studio.wav` 和 `edge-cache.wav` 做逐点比较。

做完差分以后，会发现：

- 不是所有采样点都有变化；
- 变化集中在一段一段固定长度的块里；
- 每个有效块的中心区域特别稳定。

在当前这题里，比较稳定的窗口大概落在：

```text
30..34
```

而这一小段的幅值可以很自然地分成四档。归一化后，大致会落成：

```text
9, 19, 29, 39
```

把这四档映射成四元符号后，就能得到后面真正用来做同步和组帧的主符号流。

这一步也是整题最关键的转折点：  

一旦你确认“数据在差分里，而且中心窗口稳定”，后面的 framing 就不再是盲猜了。

---

## 六、同步字、帧头和重组顺序

题目在 session 元数据里已经提前埋了三条线：

- `frame_sync_symbols = 8`
- `frame_fields = ["index", "length"]`
- `frame_order = "indexed"`

所以当四元符号流提取出来以后，最自然的事情就是先找一个稳定重复出现的 8-symbol 模式。

这题里能找到的同步字是：

```text
(3, 1, 0, 3, 2, 1, 0, 1)
```

同步字后面紧跟的就是帧头。结合题目给出的提示，可以把头部解释成：

- `index`
- `length`

做到这里以后，原本有些乱序的片段就能按 `index` 重组起来，这和 `frame_order = indexed` 完全对应。

也就是说，这一步不是“拍脑袋猜字段”，而是拿题目已经给出的 framing 约束去对齐实际观测。

---

## 七、Hamming(7,4) 和 CRC16 的作用

题目头部里已经明确告诉了纠错方式：

```text
X-Stream-FEC: hamming-7-4
```

所以后面的比特流不能直接当正文看，而是要按 Hamming(7,4) 去还原有效 nibble。  

另外，每帧还带了 `crc16`。这一步非常重要，因为它不仅仅是“最后验一下”，更是在排除错误解析。

现实里做这种题，经常会遇到一种情况：  

某套切分或映射看起来也能跑出一堆数据，但只要 CRC 一验就知道是错的。

这题也是一样。  

只有在：

- 同步字找对了；
- 帧边界切对了；
- `index/length` 解释对了；
- Hamming 纠错方向也对了；

之后，CRC16 才会稳定通过。

所以 CRC 这里不是可有可无，而是整条链最后的“定盘星”。

---

## 八、最后为什么会得到 base64

经过前面的恢复以后，拿到的还不是明文 flag，而是一段被 XOR 处理过的数据。  

这里就回到了前面从流量里拿到的 key。用那条由请求顺序派生出来的 SHA-256 key 去做 XOR，结果会变成一段很像文本的内容。

继续看可以发现，它其实是一段 base64。

再做一次 base64 解码，最终得到 flag：

```text
SCTF{stream_order_meets_noisy_rhythm}
```

---

## 总结

这题表面上是 Misc，但其实信息给得并不吝啬。  

真正关键的是不要把这些提示割裂开看：

- incident 回包提醒你抓包不完整，所以要做 Range 重组；
- session 元数据告诉你节奏、同步字长度、帧字段和校验方式；
- 两路音频的差分提供真正的数据承载层；
- Hamming 和 CRC 则负责把中间那些“看起来像对了”的结果筛到只剩真正正确的那一条。

如果顺着这个思路走，题目整体会比较顺；  
如果一开始就跳进音频里盲猜编码，反而会很费时间。
