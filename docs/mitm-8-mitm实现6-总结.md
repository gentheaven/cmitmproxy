# mitm-8-项目总结

2025/12/25 写



# 1 - 代码

2个代码：

一个是 MITM 代理：编译为动态链接库。

一个是微信短视频下载，使用了 MITM 代理技术。



码云：

```
全球唯一，纯c语言实现，windows运行的MITM代理
https://gitee.com/gentheaven/cmitmproxy


下载微信短视频
https://gitee.com/gentheaven/we-chat-video
```



GitHub

```
The world's only MITM proxy implemented purely in C language and running on Windows
https://github.com/gentheaven/cmitmproxy

WeChat videos download
https://github.com/gentheaven/WeChatVideo
```



# 2- 文章

以下文章，包括本文，相当于本项目的技术文档。

[mitm-1-实现思路 - 知乎](https://zhuanlan.zhihu.com/p/1979186130697082266)

[mitm-2-使用 mtim库 - 知乎](https://zhuanlan.zhihu.com/p/1981354362463859347)

[mitm-3-mitm实现1-总体架构 - 知乎](https://zhuanlan.zhihu.com/p/1981642421898085460)

[mitm-4-mitm实现2-破解https - 知乎](https://zhuanlan.zhihu.com/p/1984344015877997443)

[mitm-5-mitm实现3-假证书 - 知乎](https://zhuanlan.zhihu.com/p/1986144605582942558)

[mitm-6-mitm实现4-中间层 - 知乎](https://zhuanlan.zhihu.com/p/1986694682420483092)

[mitm-7-mitm实现5-修改网页 - 知乎](https://zhuanlan.zhihu.com/p/1986733580605473879)



# 3 - 调试

如果需要调试，需要**打开 DEBUG 宏**，在 proxy.h 中。

```
#define DEBUG
```

打开 DEBUG 宏后，代理会输出会话密钥，Wireshark 可以破解 https 流量。

注意：打开这个宏之后，还需要设置windows 全局代理为： 127.0.0.1:8080，

本机的http 流量才会经过代理程序。

（平时运行时，没有打开DEBUG 宏，应用会自动设置  windows 代理）

用 Visual Studio 2022 社区版，可以加断点，**单步调试**，随时查看内存，变量内容。

尤其是调试 TLS 握手，curl https 时很方便。



## 3.1 调试TLS 握手

无需设置全局 windows 代理。

用 nginx, openssl 测试 TLS 握手

```bash
openssl s_client -connect localhost:443  -proxy 127.0.0.1:8080 -brief 
```

这样做，只有这一个连接请求经过代理，调试很方便。

如果终端输出以下内容，则说明完成 TLS 握手，本功能测试通过。

```
Connecting to 127.0.0.1
depth=0 C=CN, CN=albert
verify error:num=20:unable to get local issuer certificate
depth=0 C=CN, CN=albert
verify error:num=21:unable to verify the first certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: C=CN, CN=albert
Hash used: SHA256
Signature type: rsa_pss_rsae_sha256
Verification error: unable to verify the first certificate
Peer Temp Key: X25519, 253 bits
```

verify error：openssl 验证证书失败，这不是错误。

openssl 对所有的自签名证书，都验证失败。



## 3.2 调试 https

无需设置全局 windows 代理。

用 nginx，curl 调试 windows 代理。

```bash
curl -x 127.0.0.1:8080  -k -v  https://localhost
```

这样做，只有这一个连接请求经过代理，调试很方便。

如果终端输出网页内容，则本功能测试通过。这个网页是 nginx 服务器的 index.html 的内容。

```
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```



## 3.3 测试雪球网站

以上两步调试通过后，再用实际网站测试。

此时无需启动 Nginx。

需要设置全局 windows 代理。

打开以下网站， 替换它的主页：

```
https://xueqiu.com/
```

如果发现主页内容被替换为 **hello world** ，则测试通过。

![changed](../resources/changed.jpg)

------



# 4 - 内存释放

cmitmproxy 编译为动态链接库。

应用层使用这个库实现https 破解，而无需关注内部实现。

现在有一个问题：如果在应用层申请一个缓冲区，然后传到动态链接库。

只有动态链接库知道什么时候释放这个缓冲，怎么实现这个功能？

即应用程序和动态链接库之间，如何管理内存的申请和释放？



```c
typedef void (*FreeFunc)(void*);
/*
* in:
       arg: in/out used for app
	   info: http info

   out: 
        if changed html content, put changes to out[out_len]
		free_func:
			proxy will call  cb_free(out) after use it
			if cb_free is NULL, proxy not free
		e.g.
		*cb_free = NULL, proxy not free memory;
		*cb_free = free, proxy will call free(out)
return:
    if changed html content, return 1; 
    otherwise return 0
*/
typedef int (*cb_http_response)(
	void* arg, http_info_t* info, //in
	char** out, size_t* out_len, FreeFunc* cb_free); //out
void register_action_cb_http(mitm_ctx* ctx, cb_http_response on_response);
```

最重要的原则：谁申请，谁释放。

内存是在应用中申请的，就要由应用提供释放函数。

这里用了函数指针的指针，把这个释放函数告诉动态链接库。

动态链接库会在合适的时机，释放指针。

```c
typedef void (*FreeFunc)(void*);
FreeFunc* cb_free;
```



比如，上面的测试中，应用程序替换雪球网站的主页，

应用层代码这样做：

```c
static char html_changed[] = "\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
<title>Changed content</title>\n\
</head>\n\
<body>\n\
<p><em>hello world.</em></p>\n\
</body>\n\
</html>\n\
";
int http_response(
	void* arg, http_info_t* http_ctx, //in
	char** out, size_t* out_len, FreeFunc* cb_free)
{
    size_t len = strlen(html_changed);
    buf = malloc(len);
	memcpy(buf, html_changed, len);
    *out = buf;
    *out_len = len;
    *cb_free = free; //应用程序提供释放函数
}
register_action_cb_http(mitm, http_response);
```

应用程序：申请内存，把修改后的网页内容传给动态链接库。这属于应用层逻辑。

代理（动态链接库）：把修改后的内容转发后，释放内存。

只有动态链接库才知道什么时候应该释放内存，但是它不知道如何释放，所以需要应用把函数地址传给它。

就是这个问题，困扰了我很久。

如果在动态链接库中，直接使用 free(buf)，则会出现不可预料的随机错误。



核心原则：**谁申请，谁释放**

内存管理的基本原则是 **分配和释放应该在同一个内存管理上下文中进行**。这是因为：

1. **不同的堆（Heap）管理器**
   - 应用程序和DLL可能使用不同的运行时库（如不同版本的MSVC运行时）
   - 每个模块可能有自己独立的堆管理器
   - 在A的堆上分配，在B的堆上释放会导致未定义行为（崩溃、内存损坏）
2. **不同的编译选项**
   - 即使使用相同的编译器，如果编译选项不同（如调试/发布版），内存布局可能不同

更具体的，可以看这篇文章：

https://zhuanlan.zhihu.com/p/684561249





# 5 - 总结

原先计划：

| 阶段                       | 时间                   | 时长   |
| :------------------------- | :--------------------- | :----- |
| mitmproxy Python 技术栈    | 2025/8/1 - 2025/8/27   | 1个月  |
| 预研：c 语言实现 mitmproxy | 2025/9/1 - 2025/9/12   | 半个月 |
| 实现https 代理             | 2025/9/15 - 2025/9/30  | 15天   |
| 学习 SSL 协议              | 2025/10/1 - 2025/11/30 | 2个月  |
| 实现 MITM 代理             | 2025/12/1 - 2026/2/28  | 3个月  |
| 纯C 技术栈实现微信视频下载 | 2026/3/1 - 2026/3/31   | 1个月  |
|                            |                        |        |
| 合计时间                   | 2025/8/1 - 2026/3/31   | 8个月  |



实际执行：

| 里程碑                 | 完成事项                               | 时长    |
| :--------------------- | :------------------------------------- | :------ |
| 2025/8/1 - 2025/8/31   | 下载微信短视频，Python 技术栈          | 1个月   |
| 2025/9/1 - 2025/9/12   | 预研：c 语言实现 mitmproxy             | 半个月  |
| 2025/9/15 - 2025/9/30  | 实现 https 代理，基于 libuv 开源库     | 半个月  |
| 2025/10/1 - 2025/11/4  | 完成 Openssl-dec 项目                  | 1个月   |
| 2025/11/5 - 2025/12/25 | 实现 MITM 代理，纯C 技术栈微信视频下载 | 1.5个月 |
|                        |                                        |         |
| 合计时间               | 2025/8/1 - 2025/12/25                  | 4个月   |

备注：**Openssl-dec** 项目是为了学习 SSL 协议而立项，学习型项目。

做完这个项目，对于理解 SSL 协议，OpenSSL 开源库，很有用。



为什么实际执行的时间大大缩短？

主要是因为改变了实现框架。

本来用 libuv 库实现，需要自己实现加密和解密，很复杂，所以需要很多时间。

后来用 libevent 实现，libevent 替你封装了 OpenSSL，无需自己实现加密和解密，

大大简化了开发过程，所以项目时间大大缩短。



# 6 - 预告

下一篇文章，讲述如何用 mitm 实现微信短视频下载。

之前用Python 技术栈实现，现在用自己开发的 mitm ，纯c 技术栈实现，效果如何？

敬请期待。