# mitm-3-mitm实现1-总体架构

2025/12/9 写

现在开始讲解 MITM代理是如何实现的。

本文只讲解总体架构。



# 工作模式



## 2种模式

有2种工作模式：

1. forward 直通模式：MITM 直接转发数据，不解密。和 http/https 代理一样。
2. mitm 解密模式：MITM 可能会解密，还取决于过滤系统。

```c
enum WORK_MODE {
    WORK_MODE_FORWARD = 0, //HTTPS proxy
    WORK_MODE_MITM //mitm proxy
};
```





## 总框架图

如果工作模式设置为 **WORK_MODE_FORWARD**，则系统相当于 http/https 代理，只转发，而不关心内容。

工作原理如下：

```mermaid
flowchart LR

client[客户端<br>例如浏览器]
proxy[代理]
server[Web服务器]

client <-- 只转发 --> proxy
proxy -- 只转发 --> server
```



如果工作模式设置为**WORK_MODE_MITM**，则系统工作在 mitm 代理模式，将会解密 HTTPs 流量。

类似 mitmdump。工作原理如下：

```mermaid
flowchart LR

client
server
filter


subgraph filter_result[filter result]
pass
split
end

subgraph filter_system[Application callback function]
filter
filter_result
end

client <----> filter
filter <----> filter_result

pass <-- forward --> server
split <-- decrypt --> server

```



## 过滤器 filter

用户注册一个过滤器，可以只解密关心的网络连接。

```c
enum FILTER_RESULT {
    FILTER_RESULT_PASS = 0, //forward only
    FILTER_RESULT_SPLIT, //decrypt https traffic
};
```

如果过滤器返回 FILTER_RESULT_PASS， 则这个https 连接不解密，采用直通模式；

如果过滤器返回 FILTER_RESULT_SPLIT，则解密这个https 连接。

```c
typedef enum FILTER_RESULT (*cbfilter_by_host)(const char* host_name);
void register_filter_cb_host(mitm_ctx* ctx, cbfilter_by_host cbfunc);

void mitm_set_filter_mode(struct child* pchild)
{
	struct mitm_ctx_st* ctx = pchild->mctx;
	enum FILTER_RESULT res = DEFAULT_FILTER_RESULT;

	//is CONNECT?
	int is_https = 1;
	if (strcasecmp(pchild->req.method, "connect")) {
		is_https = 0;
	}	

	if (ctx->mode == WORK_MODE_FORWARD) {
		res = FILTER_RESULT_PASS;
	} else if (!is_https) {
		// only care https
		res = FILTER_RESULT_PASS;
	} else {
		//mode is WORK_MODE_MITM, and is CONNECT request
		if (ctx->cb_host)
			res = ctx->cb_host(pchild->req.host);
	}

	pchild->filter_res = res;
}
```

流程图如下：

```mermaid
graph

client[客户端连接请求]
forward[直通模式<br>FILTER_RESULT_PASS]
split[解密模式<br>FILTER_RESULT_SPLIT]

subgraph type[连接类型]
http
https
end

subgraph mode[全局工作模式]
WORK_MODE_FORWARD[直通模式]
WORK_MODE_MITM[MITM模式]
end


client --get/post --> http --> forward
client --CONNECT  --> https
https  --> WORK_MODE_FORWARD --> forward
https  --> WORK_MODE_MITM
WORK_MODE_MITM --> filter[用户过滤器]
filter --> forward
filter --> split

```





# 工作流程



## 注意

由于许多函数调用是异步的（libevent 实现的异步功能），所以程序看着比较复杂。

以下的框图中：

**虚线**代表异步调用；**实线**代表同步调用

特别注意虚线连接。



## 1 - 初始化

```c
mitm_ctx* mitm_init(char* ip, unsigned short port);

//例如绑定本地 127.0.0.1:8080
mitm_ctx* mitm = mitm_init("127.0.0.1", 8080);
```

初始化需要两个参数：代理绑定的IP地址和端口。

mitm_init 做了如下几件事：

1. 设置windows 全局代理
2. 加载 CA 证书和 CA 私钥
3. 初始化 Windows Winsock 环境
4. 初始化 libevent
5. 设置  SIGINT (ctrl-c) 处理函数



```mermaid
graph

subgraph main[主程序]
direction TB
init[系统初始化]
listen[开始监听<br>evconnlistener_new_bind]
loop[主循环<br>event_base_dispatch]
end

init --start_proxy_server --> listen
listen  --> loop
```

## 2 - 处理客户端连接

当接收到客户端连接请求后：

```mermaid
graph
direction TB

on_new_connection
event_new["event_new(fd, EV_READ)"]
proxy_read_connect_req


subgraph proxy_read_connect_req
parse_connect_request[parse_connect_request<br>解析请求]
response[回应连接建立成功]
mitm_set_filter_mode[mitm_set_filter_mode<br>过滤器]
end

subgraph filter[过滤结果]
forward[直通模式]
split[解密模式]
end

on_new_connection --> event_new
event_new -.socket可读 .-> proxy_read_connect_req
mitm_set_filter_mode --forward --> forward
mitm_set_filter_mode --split --> split
```

这里为什么用 event_new 监听客户端请求，而不是直接调用 bufferevent_socket_new 来监听客户端请求？

因为这时还不知道用直通模式还是解密模式。

确定模式后（调用 mitm_set_filter_mode 函数后），才能创建  bufferevent 。

直通模式：**bufferevent_socket_new**，建立TCP 连接；无需解密，直接转发数据

解密模式： **bufferevent_openssl_socket_new**，建立SSL 连接；可以解密https



## 3 - 直通模式



```mermaid
graph

subgraph opensock_pass
server[bufferevent_socket_new<br>创建服务器socket]
dns[bufferevent_socket_connect_hostname<br>发起DNS查询]
end

subgraph set_passthrough_mode
client[bufferevent_socket_new<br>创建客户端socket]
opensock_pass[opensock_pass<br>尝试连接服务器]
end

opensock_pass  .-> server_eventcb
server_eventcb --与服务器连接成功<br>BEV_EVENT_CONNECTED --> on_connect_remote_server
on_connect_remote_server --> relay_connection[relay_connection<br>转发数据]

proxy_read_connect_req --> set_passthrough_mode
```



## 4 - 解密模式

先来一个 TLS 握手阶段的示意图：

```mermaid
sequenceDiagram
autonumber

participant client as 客户端
participant proxy  as 代理
participant server as 服务器


client ->> proxy: 连接请求
proxy  ->> client: 连接建立
client ->> proxy: 第一次握手报包含SNI
proxy  ->> server: 第一次握手报包含SNI
server ->> proxy: CN and SANs
proxy  ->> client: 完成握手
client ->> proxy: 开始通讯
proxy  ->> server: 开始通讯
```

当 proxy_read_connect_req 执行完毕时，已经完成了第1步和第2步。

现在准备处理第3步到第6步。

```mermaid
graph
proxy_read_connect_req
event_new["event_new(fd, EV_READ)"]

subgraph protossl_fd_readcb
ssl_tls_clienthello_parse[ssl_tls_clienthello_parse<br>得到SNI]
opensock[opensock]
end

proxy_read_connect_req --> event_new
event_new -.socket可读 .-> protossl_fd_readcb

opensock -.发起DNS请求 .-> on_resolved
on_resolved --> pxy_conn_connect[pxy_conn_connect<br>和远程服务器连接]


```

**和服务器连接**

代理作为客户端，和远程服务器连接

```mermaid
graph

subgraph pxy_conn_connect[pxy_conn_connect]
protossl_dstssl_create[protossl_<br>dstssl_create]
protossl_bufferevent_setup[protossl_<br>bufferevent_setup]
bufferevent_setcb["bufferevent_setcb<br>(protossl_bev_eventcb)"]
bufferevent_socket_connect[bufferevent_<br>socket_connect]
end

bufferevent_socket_connect -.连接远程服务器 .-> server
protossl_bufferevent_setup --> bufferevent_openssl_socket_new["bufferevent_openssl_<br>socket_new(ssl)"]
protossl_dstssl_create --> SSL_new["ssl=SSL_new()"]

bufferevent_setcb  .-> protossl_bev_eventcb
protossl_bev_eventcb --和服务器连接成功 --> 和客户端连接
```



**和客户端连接**

代理作为服务器，和客户端连接。

```c
bufferevent_setcb(ctx->conn.server_socket, NULL, NULL, protossl_bev_eventcb, ctx);
```

当和远程服务器建立连接后，会调用 protossl_bev_eventcb

```mermaid
graph


subgraph protossl_bev_eventcb_connected_srvdst
protossl_enable_src["设置客户端<br>protossl_enable_src"]
protossl_srcssl_create["ssl=<br>protossl_srcssl_<br>create(server_ssl)"]
end

subgraph protossl_srccert_create[代理作为服务器]
ssl_x509_forge[ssl_x509_forge<br>创建证书]
SSL_new["ssl=SSL_new()"]
end

protossl_bev_eventcb --服务器事件 -->protossl_bev_eventcb_srvdst
protossl_bev_eventcb_srvdst --BEV_EVENT_CONNECTED --> protossl_bev_eventcb_connected_srvdst
protossl_srcssl_create --> protossl_srccert_create
bufferevent_openssl_socket_new -.和客户端建立SSL连接 .-> client

protossl_enable_src --> bufferevent_openssl_socket_new
```



# 下一步

直通模式下：代理分别和客户端和服务器端建立了 **TCP 连接**，直接转发数据，无需加密和解密；

解密模式下：代理分别和客户端和服务器端建立了 **SSL 连接**。

那么，代理是如何加密和解密呢？

下一篇文章讲解。

