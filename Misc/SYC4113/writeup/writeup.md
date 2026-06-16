# SYC4113

## 结论

最终解出的邮件入口为：

```text
SYC218138593@163.com
```

计算依据：

```text
523 * 631 * 661 = 218138593
```

其中 `523` 来自最后的语音提示，`631` 与 `661` 来自初始图片 `final.png` 的尺寸 `631x661`，且三者均为质数。

后续向该邮箱发送邮件即可获得真正的 flag。

## 解题过程

### 1. PNG 文件尾部附加数据

初始文件：

```bash
file final.png
binwalk final.png
```

文件类型为 PNG，尺寸为 `631x661`。`binwalk` 显示 PNG 正常结束，但实际文件在 `IEND` 后还有尾随数据。

可用脚本提取 PNG 逻辑结束后的数据：

```python
from pathlib import Path

p = Path("final.png").read_bytes()
iend = p.find(b"IEND")
tail = p[iend + 8:]
print(tail)
```

尾部内容为：

```text
JLHZHYZH`ZAo{{wzA66ptn5jku85}pw6p6=h9h=h9j?@i7?f8>?88=;<??5qwn
```

根据 hint1 “尝试枚举下 ASCII 的 CEASAR”，对 ASCII 128 空间枚举 Caesar 位移。位移 `-7` 可得到：

```text
CEASARSAYS:https://img.cdn1.vip/i/6a2a6a2c89b08_1781164588.jpg
```

脚本示例：

```python
s = b"JLHZHYZH`ZAo{{wzA66ptn5jku85}pw6p6=h9h=h9j?@i7?f8>?88=;<??5qwn"
for shift in range(128):
    out = bytes((c + shift) % 128 for c in s)
    if b"http" in out or b"CEASAR" in out:
        print(shift, out.decode(errors="replace"))
```

### 2. JPG 第二阶段与 outguess

下载 Caesar 解出的 JPG：

```bash
curl -L -o analysis/stage2.jpg \
  'https://img.cdn1.vip/i/6a2a6a2c89b08_1781164588.jpg'
```

图片文字中出现：

```text
guess the hidden message out
```

这里 `guess ... out` 明显提示 `outguess`。

使用空密码提取：

```bash
outguess -r analysis/stage2.jpg analysis/outguess_empty
```

提取内容：

```text
URL:https://www.iplant.cn/foc/pdf/Fabaceae.pdf
VHJpZm9saXVtIHJlcGVucw==550
2:4:2:1
2:7:8:4
2:9:7:2
2:10:6:1
3:1:2:7
3:2:1:6
4:1:1:9
4:2:6:1
4:4:8:3
5:1:4:9
6:1:1:5
7:1:1:4
7:7:2:1
7:9:1:6
9:1:3:6
9:1:4:2
9:3:5:1
9:3:10:2
9:5:2:8
9:11:2:4
11:1:6:6
11:2:5:6
11:3:1:4
11:4:4:2
11:5:4:6
12:1:1:9
12:1:4:3
```

其中：

```text
VHJpZm9saXVtIHJlcGVucw== -> Trifolium repens
```

`550` 指向 PDF 第 550 页。

### 3. PDF 书页坐标

下载 PDF：

```bash
curl -L -o analysis/Fabaceae.pdf \
  'https://www.iplant.cn/foc/pdf/Fabaceae.pdf'
```

生成第 550 页的文本与 bbox：

```bash
pdftotext -f 550 -l 550 -layout analysis/Fabaceae.pdf analysis/page550_layout.txt
pdftotext -f 550 -l 550 -bbox-layout analysis/Fabaceae.pdf analysis/page550_bbox.html
```

hint2 给出坐标规则：

```text
第一维指的是自然段号，所有缩进两格的自然段从左到右依次排序
```

按第 550 页所有首行缩进约两格的自然段编号，左栏从上到下，再到右栏从上到下；第 7 段从左栏底部跨到右栏顶部，需要把跨栏续行合并到同一自然段。

我整理出的 12 个自然段为：

```text
1. Cold coniferous forests...
2. Trifolium repens 描述段：Perennial herbs...
3. Trifolium repens 分布段：Cultivated, escaped...
4. Trifolium hybridum 描述段：Perennial herbs...
5. Trifolium hybridum 分布段：Cultivated, escaped...
6. Trifolium aureum 异名段：Trifolium agrarium...
7. Trifolium aureum 描述段：Annual herbs...，跨到右栏顶部
8. Trifolium aureum 分布段：Cultivated, escaped...
9. Trifolium campestre 描述段：Annual herbs...
10. Trifolium campestre 分布段：Cultivated, escaped...
11. Trifolium dubium 描述段：Annual herbs...
12. Trifolium dubium 分布段：Cultivated, escaped...
```

按坐标 `段号:段内行号:词号:字符号`，1-based 提取，得到：

```text
https://wwbrd.lanzoum.com/sycsecret
```

### 4. 蓝奏云下载 secret.zip

访问：

```text
https://wwbrd.lanzoum.com/sycsecret
```

页面标题为：

```text
secret.zip
```

下载后压缩包内容：

```bash
unzip -l analysis/secret_real.zip
```

结果：

```text
hint.wav
morse.mp3
```

### 5. Morse 音频

`morse.mp3` 是标准摩斯码音频。转成 wav 后按短时能量切分：

```bash
ffmpeg -y -i analysis/secret/morse.mp3 -ac 1 -ar 44100 analysis/secret/morse.wav
```

检测到时间单元大致为：

```text
点：0.13s
划：0.36s
字母间隔：0.35s
单词间隔：0.83s
```

自动解码结果：

```text
CONTACT US USING SYC FOLLOWED BY THE PRODUCT OF THREE PRIME NUMBERS AND A 163 EMAIL ADDRESS.
```

也就是需要构造：

```text
SYC + 三个质数的乘积 + @163.com
```

### 6. hint.wav 语音提示

`hint.wav` 为 8 秒人声。使用 Vosk 小模型识别结果为：

```text
well done now you need to find three prime numbers one of which is five hundred and twenty three good luck
```

即三个质数中有一个是：

```text
523
```

另外两个质数来自初始图片尺寸：

```bash
file final.png
```

输出：

```text
PNG image data, 631 x 661, 8-bit/color RGB, non-interlaced
```

验证：

```python
import sympy as sp

nums = [523, 631, 661]
prod = 1
for n in nums:
    print(n, sp.isprime(n))
    prod *= n
print(prod)
```

结果：

```text
523 True
631 True
661 True
218138593
```

最终构造邮箱：

```text
SYC218138593@163.com
```

### 7. 邮件交互获取 flag

向上一步构造出的邮箱发送邮件，即可收到最终 flag：

```text
SYC218138593@163.com
```

### 8.最终flag

```plaintext
Transmission accepted.

The image lied.
The flower indexed the path.
The signal named the ritual.
The primes opened the mailbox.
You are not early.
But you are worth it:SCTF{A_voice_from_a_high_place_naturally_carries_far-it_is_not_relying_on_the_autumn_wind}

4113
```