## phpStilAlive
## Description
php sandbox!!
## Author
GSBP


## Solutions

这题的出题兴趣来自于前段时间php不断爆发的UAF漏洞，于是拿了一个广为人知的`Serializable UAF`漏洞来出了一下题
关于此漏洞的分析可以看下面的链接:
https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a

对于绕过disabled_function以外，还有一个UAF漏洞较为好用,不过在这次出题中我ban掉了`DateInterval`类让这个漏洞失效掉了
https://github.com/m0x41nos/TimeAfterFree
