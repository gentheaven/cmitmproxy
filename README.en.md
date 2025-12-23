# MITM proxy

# Description




# Software Architecture



## 1- level

3 levels:

1. app
2. mid
3. proxy

```mermaid
graph LR

app[app<br>Transaction Logic]
mid[mid<br>Parsing<br>HTTP header]
proxy[proxy<br>Crack HTTPs]

app <--> mid
mid <--> proxy
```



## 2 - implementation

```mermaid
graph LR

subgraph openssl
libssl[libssl<br>TLS]
libcrypto[libcrypto<br>Encryption<br>decryption]
end

libevent <-- plaintext --> libssl
libssl --> libcrypto
libcrypto <-- ciphertext --> TLS <--> TCP
```



## 3 - filter system

```mermaid
flowchart

filter1[filter by<br>host name]
filter2[filter by<br>http header]


subgraph filter_system[filter_system]
filter1
decoder
filter2
end

client --> filter1
filter1 --not pass --> forward
filter1 --pass --> decoder
decoder --> filter2

filter2 --not pass --> forward
filter2 --pass --> app
app --> encoder

encoder --> server
forward --> server
```



# Installation

1.  xxxx
2.  xxxx
3.  xxxx

# Instructions

1.  xxxx
2.  xxxx
3.  xxxx

# Contribution

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


# Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
