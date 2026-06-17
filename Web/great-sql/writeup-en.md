## great-sql
## Description
Where is sqlMaster?

## Author
GSBP

## Solutions
This challenge is based on a zero-day vulnerability in Apache Calcite that was recently discovered using AI (and has not yet been publicly disclosed). It was used in the SCTF competition. To make the challenge slightly harder, an additional length restriction was placed on the input parameters, but this seems to have added little difficulty given that agents were used to solve it.

The vulnerability arises because `jdbc:calcite:` allows arbitrary inline properties to be injected, and these inline properties can support registering Java methods as SQL methods. This effectively creates a UDF (User-Defined Function) vulnerability. The intended solution uses the following two inline models to register methods:

```java
MODEL = (
    "inline:{version:1,schemas:[{name:0,functions:["
    "{className:'org.codehaus.commons.compiler.samples.DemoBase',methodName:'*'},"
    "{className:'org.codehaus.janino.ClassBodyEvaluator',methodName:'*'}"
    "]}]}"
)
```

There are many ways to bypass the length restriction. Looking at the write-ups from competing teams, it turns out the length limit I set was still too permissive XD. Methods include:

- Shortening the inline model string
- Sending the payload in multiple parts
- Modifying the original JSON structure by removing unnecessary attributes
- And more...

The intended solution used OOB (Out-of-Band) exfiltration to retrieve the flag. However, other teams also succeeded with a two-step exploit: first executing `/readflag` and redirecting the result to a readable file, and then registering a file-reading function to read the flag from that file.

(Translate by Deepseek)