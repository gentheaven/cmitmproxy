# mitm-7-mitm实现5-修改网页

2025/12/23 写

# 前言

之前的文章，

MITM代理：已经破解了https：相当于原始食材

中间层：对原始食材深加工，做成可口的饭菜

应用层：大多数时候直接吃即可，即直接查看 http 的内容，不做修改。

有时候，应用层想修改网页的内容，如何做？

相当复杂。

本文就讲述一个最复杂的例子，但是实际应用中很有用的。



# 微信视频

最近做一个微信视频下载 app， PC 上运行的。

简要过程：

当你用 PC 上的微信观赏微信视频时，如下面这个界面：

![wechat-cover](..\resources\wechat-cover.jpg)



MITM 代理会**自动截获**并记录微信短视频的 URL，视频标题，视频大小等信息。

然后根据需要，可以下载感兴趣的。界面如下：

![cover](..\resources\cover.jpg)



这是怎么做到的？

用了什么魔法？



# 实现原理

首先，微信app 和腾讯服务器的通讯是加密的，**https 加密**，这里用 **MITM 代理**破解；

其次，微信短视频的相关信息，不会直接体现在通讯内容里；相关信息再 Javascipt 脚本里，无法破解。

怎么办？

需要逆向微信的通讯协议，很难做。



## 正则表达式

不如直接修改原始的 Javascipt 文件。用正则表达式修改。

正则表达式如下：c 语言实现正则表达式替换字符串

```c
regex_match_str = "async finderGetCommentDetail\\((\\w+)\\)\\{return(.*?)\\}async";
regex_replace_str = "async finderGetCommentDetail(\\1){const feedResult=await\\2;var data_object=feedResult.data.object;var media=data_object.objectDesc.media[0];var fetch_body={duration:media.spec[0].durationMs,title:data_object.objectDesc.description,url:media.url+media.urlToken,size:media.fileSize,key:media.decodeKey,id:data_object.id,nonce_id:data_object.objectNonceId,nickname:data_object.nickname,createtime:data_object.createtime,fileFormat:media.spec.map(o => o.fileFormat)};fetch('https://www.httpbin.org/post',{method:'POST',headers:{'Content-Type':'application/json',},body:JSON.stringify(fetch_body)}).then(response=>{console.log(response.ok,response.body)});return feedResult;}async";

size_t len = ori_len + 1024;
char* chg_content = malloc(len);
*chg_len = len;
regex_replace(ori, (unsigned int)ori_len,
		regex_match_str, regex_replace_str, chg_content, chg_len, 1);
```



## 原始文件

原始文件如下：只展示修改的部分，源文件大小 40KB

```javascript
async finderGetCommentDetail(t) {
      return this.post({
        name: "FinderGetCommentDetail",
        data: {
          finderBasereq: {...this.finderBasereq,
            exptFlag: 1,
            requestId: Ve()
          },
          platformScene: 2,
          ...t
        }
      })
    }
```



## 修改后的

修改后的文件如下：只展示修改的部分

```javascript
async finderGetCommentDetail(t) {
      const feedResult = await this.post({
        name: "FinderGetCommentDetail",
        data: {
          finderBasereq: {...this.finderBasereq,
            exptFlag: 1,
            requestId: Ve()
          },
          platformScene: 2,
          ...t
        }
      });
      var data_object = feedResult.data.object;
      var media = data_object.objectDesc.media[0];
      var fetch_body = {
        duration: media.spec[0].durationMs,
        title: data_object.objectDesc.description,
        url: media.url + media.urlToken,
        size: media.fileSize,
        key: media.decodeKey,
        id: data_object.id,
        nonce_id: data_object.objectNonceId,
        nickname: data_object.nickname,
        createtime: data_object.createtime,
        fileFormat: media.spec.map(o = >o.fileFormat)
      };
      fetch('https://www.httpbin.org/post', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(fetch_body)
      }).then(response = >{
        console.log(response.ok, response.body)
      });
      return feedResult;
    }
```



# 修改流程



## http包

分为以下步骤：全流程，从http 层面看：

1. 客户端向服务器请求 JS 文件：

   GET /t/wx_fed/finder/web/web-finder/res/js/virtual_svg-icons-register.publishDJmRcesj.js HTTP/1.1\r\n

2. 代理转发请求；

3. 服务器回应原始的JS 文件；

4. 代理破解后，把http 响应（包含 JS 文件）发送给中间层；

5. 中间层把重组，解压后的JS 文件传给应用层；

6. 应用层修改 JS 文件，把修改后的文件传给中间层；

7. 中间层压缩，添加 http 头，传给代理层

8. 代理层转发修改后的文件给客户端

这里，客户端是 PC 上的微信app，服务器是腾讯服务器。



## 代码层

代码中，具体实现如下：

1. 代理层：**破解 https**，把破解后的内容发给中间层
2. 中间层：**解析HTTP头**。得到 http 长度。Content-Length: **131323**
3. 中间层：**组包**。读取收到的http 响应，把内容组合到一个缓存中，直到组包后的长度为 **131323** 字节
4. 中间层：**解压缩**。Content-Encoding: br 。压缩格式是 br，解压为 **413942**  字节。解压后的内容传给应用层
5. 应用层：**修改 Javascipt** 文件。修改后的内容传给中间层，修改后长度为 **414569** 字节
6. 中间层：**压缩**。把应用层修改后的内容，压缩为 br 格式，压缩后长度为 **156073** 字节
7. 中间层：**组包**。Javascipt 文件内容，加上 http 头，不要忘了还要改变 Content-Length 字段的内容。发给代理层
8. 代理层：代理层转发修改后的http 包给客户端

整个过程的官方名称，称为代码注入，**inject**。

修改后的代码，会给服务器 https://www.httpbin.org/post 发送视频的相关信息。

```javascript
 fetch('https://www.httpbin.org/post', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(fetch_body)
      }).then(response = >{
        console.log(response.ok, response.body)
      });
```



## 结果如下

可以获取 http POST JSON 数据，其中包含视频的信息。

```
POST /post HTTP/1.1
Host: www.httpbin.org
Connection: keep-alive
Content-Length: 1201
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541518) XWEB/17071 Flue
Content-Type: application/json
Accept: */*
Origin: https://channels.weixin.qq.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://channels.weixin.qq.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9

{"duration":25934,"title":"全网寻求高端客户入住。 \n缓山铂岭单身公寓豪华装修带院子。\n把家安在公园里 你喜欢么#同城房产 #房产 #我要上热门","url":"https://finder.video.qq.com/251/20302/stodownload?encfilekey=Cvvj5Ix3eez3Y79SxtvVL0L7CkPM6dFibFeI6caGYwFHT3XaR9NPibIrOZuHtuTlr67UJpgbLQdNjaewYV4yaDcCgmicAibLuzibyvtibSyqSsNbIibrMQgox3piag4c7h0RIoJzlSZPd5CXl10ewjQYu5zStg&hy=SH&idx=1&m=f8b0e96b0e6d39f687fd39fad40990ff&uzid=7a15c&token=AxricY7RBHdXIV731WxZwqscgXzEU0CatLvYHuBlKVhADnkmByB2CPpm0kNp7Opt4kGJw6YWtuhSukUso7VFVPdl1L39f1dAETlD62tNXUFIRPIR9gPPe6Dic3rbAO79xuY9Eicicgv7HVyJbG2cWDZI0blicStLdo16hDyAFbgGqqhQ&basedata=CAESABoDeFYwIgAqBwiLKRAAGAI&sign=o-KqaCUkgsuspY3uiisNelCpBwvj6N24xcKzf4rJNtmV8xJvPa3B3JyWpK9bCRZ2GiSHfYRSoM81IFZ23WBVhg&ctsc=141&web=1&extg=4f0000&svrbypass=AAuL%2FQsFAAABAAAAAAC4ZhpO8DrFI8gQM0M%2FaRAAAADnaHZTnGbFfAj9RgZXfw6VeW3j4tgsxICTvMFOWYZJRxS%2BV0uU8YLf%2FeXG8T5eti2GhsVk2n%2Bqt9A%3D&svrnonce=1765753651","size":22032097,"key":"1374101633","id":"14720317918180542501","nonce_id":"16620950404437459775_0_141_0_0","nickname":"欣家冰雪","createtime":1754798640,"fileFormat":["xWT111","xWT112","xWT113","xWT156","xWT157","xWT158"]}
```



# Wireshark 结果

用Wireshark 同时在本地和LAN 口抓包。



## 原始内容

原始的JS 文件，**腾讯服务器回应给代理**的结果。

可以看到：

Content-Length: **131323**

Content-encoded entity body (br): 131323 bytes -> **413942** bytes

```http
Hypertext Transfer Protocol
    HTTP/1.1 200 OK\r\n
    Last-Modified: Wed, 10 Dec 2025 08:22:45 GMT\r\n
    Content-Encoding: br\r\n
    Etag: "761f3b295fd4ccbf0d7ad709de881fd3"\r\n
    Content-Type: application/javascript\r\n
    Content-Length: 131323\r\n
    Accept-Ranges: bytes\r\n
    X-NWS-LOG-UUID: 8530997749576461560\r\n
    Connection: keep-alive\r\n
    Server: Lego Server\r\n
    Date: Wed, 10 Dec 2025 20:14:25 GMT\r\n
    X-Cache-Lookup: Cache Refresh Hit\r\n
    Vary: Origin\r\n
    Cache-Control: max-age=31536000\r\n
    Access-Control-Allow-Origin: *\r\n
    \r\n
   
    Content-encoded entity body (br): 131323 bytes -> 413942 bytes
    File Data: 413942 bytes
```



## 修改后

修改后的：代理层发送给PC微信app 的结果。

可以看到：

Content-Length: **156073**

Content-encoded entity body (br): 156073 bytes -> **414569** bytes

```http
Hypertext Transfer Protocol
    HTTP/1.1 200 OK\r\n
    Last-Modified: Thu, 11 Dec 2025 07:42:00 GMT\r\n
    Content-Encoding: br\r\n
    Etag: "4c25bc4ebd59fc02df4240ff4489d5fa"\r\n
    Content-Type: application/javascript\r\n
    Content-Length: 156073\r\n
    Accept-Ranges: bytes\r\n
    X-NWS-LOG-UUID: 1887934505537470517\r\n
    Connection: close\r\n
    Server: Lego Server\r\n
    Date: Sun, 14 Dec 2025 23:05:11 GMT\r\n
    X-Cache-Lookup: Cache Hit\r\n
    Vary: Origin\r\n
    Cache-Control: max-age=31536000\r\n
    Access-Control-Allow-Origin: *\r\n
    \r\n
   
    Content-encoded entity body (br): 156073 bytes -> 414569 bytes
    File Data: 414569 bytes
```

当同时抓到这两个包，说明修改成功。

修改成功后，微信客户端就会发送我们需要的信息：包含视频标题，长度，下载用的URL，加密种子等信息。

------



# 总结

经过复杂而漫长的流程，我们终于修改了网页的内容。

一共需要8步：

解密 https - 解析http - 组包 - 解压 - 修改 - 压缩 - 再组包 - 加密后再发送

真不容易。

无论如何，c 语言可以完成如此复杂的事情。

无论从原理，还是从实践，完美实现了修改网页（代码注入）的功能。

修改了网页，就可以下载微信短视频；保存这个视频在本地硬盘上。

即使这个短视频将来下架了，本地还有。以后可以慢慢看。

最终代码，最近会上传到“码云”和 GitHub 上，敬请期待。