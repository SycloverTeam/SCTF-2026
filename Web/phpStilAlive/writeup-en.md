## phpStilAlive
## Description
php sandbox!!
## Author
GSBP

## Solutions

The inspiration for this challenge came from the recent wave of UAF vulnerabilities that kept surfacing in PHP. I decided to use a well-known `Serializable UAF` vulnerability as the basis for this problem.

For an analysis of this vulnerability, see the following link:
https://blog.calif.io/p/mad-bugs-finding-and-exploiting-a

In addition to bypassing `disabled_functions`, there is another UAF vulnerability that is relatively easy to exploit. However, for this challenge, I disabled the `DateInterval` class, which rendered that particular vulnerability ineffective:
https://github.com/m0x41nos/TimeAfterFree