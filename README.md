# YSOCK

基于 HTTP 的 SOCKS5 隧道代理工具，通过 Web 脚本（PHP/JSP/JSPX/ASPX/ASP）在目标服务器上建立加密隧道，支持多路复用和三种传输模式自动切换。

## 特性

- **多 Payload 支持** — PHP / JSP / JSPX / ASPX / ASP
- **三模式传输** — Full Duplex / Half Duplex / Classic，自动检测最优模式
- **加密通信** — SHA256-CTR + HMAC-SHA256
- **多路复用** — 单 HTTP 连接承载多个 SOCKS5 会话

## 传输模式

| 模式 | 连接模型 | 服务端资源占用 | 适用场景 |
|------|---------|--------------|---------|
| Full Duplex | 单连接双向流（rawhttp 劫持） | 1 worker 持续占用 | JSP / 直接连接 PHP-FPM |
| Half Duplex | 流式响应 + 独立 POST 写数据 | 1 worker 持续占用 | 多 worker 环境 |
| Classic | 短连接轮询，后台线程读 TCP | 仅短暂占用 | 单 worker 环境（最通用） |
| Auto | 自动检测选择最优模式 | — | 默认推荐 |

## 构建

```shell
make build
```

## 使用

### 生成 Payload

```shell
ysock payload -t <type> -k <key> -o <output>
```

```shell
ysock payload -t php  -k mysecret -o tunnel.php
ysock payload -t jsp  -k mysecret -o tunnel.jsp
ysock payload -t jspx -k mysecret -o tunnel.jspx
ysock payload -t aspx -k mysecret -o tunnel.aspx
ysock payload -t asp  -k mysecret -o tunnel.asp
```

将生成的文件部署到目标 Web 服务器可访问的路径。

### 启动客户端

```shell
ysock client -u <url> -k <key> [-l <addr>] [-mode <mode>] [-v]
```

```shell
# 自动检测模式（推荐）
ysock client -u http://target/tunnel.php -k mysecret

# 指定 Classic 模式（适合单 worker 环境）
ysock client -u http://target/tunnel.php -k mysecret -mode classic

# 调试输出
ysock client -u http://target/tunnel.jsp -k mysecret -v

# 指定日志级别
ysock client -u http://target/tunnel.jsp -k mysecret -log-level debug
```

### 通过代理访问

```shell
curl -x socks5://127.0.0.1:1080 http://httpbin.org/get
```

浏览器设置 SOCKS5 代理为 `127.0.0.1:1080` 即可。

## 参数说明

### Client

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-u` | — | Payload URL（必填） |
| `-k` | — | 加密密钥（必填） |
| `-l` | `127.0.0.1:1080` | SOCKS5 监听地址 |
| `-mode` | `auto` | 传输模式：auto / full / half / classic |
| `-v` | false | 启用 debug 级别日志 |
| `-log-level` | — | 日志级别：debug / info / error，优先级高于 `-v` |

### Payload

| 参数 | 说明 |
|------|------|
| `-t` | Payload 类型：php / jsp / jspx / aspx / asp |
| `-k` | 加密密钥（需与客户端一致） |
| `-o` | 输出文件路径（可选，默认 `tunnel.<type>`） |

## 架构

```
Browser/Curl
    │ SOCKS5
    ▼
┌─────────┐    HTTP + Encryption    ┌──────────────┐    TCP     ┌────────┐
│  YSOCK   │ ──────────────────────▶ │  Web Payload  │ ────────▶ │ Target │
│  Client  │ ◀────────────────────── │  (PHP/JSP/…)  │ ◀──────── │ Server │
│  (Go)    │    JSON / Binary Frame  │  (Server)     │           │        │
└─────────┘                         └──────────────┘           └────────┘
```

## 环境

- Go 1.25.3+
