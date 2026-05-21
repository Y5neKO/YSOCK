# YSOCK
一款基于Web的隧道工具

## Env

go version go1.25.3

## Build

```shell
# 清理
make clean
# 构建
make build
```

## Usage

```shell
# 生成payload
ysock -t {php,jsp,asp} -k your_key -o /path/to/payload
# 连接
ysock client -u http://localhost/tunnel.jsp -k your_key -l lhost:lport -m {audo,full,half,classic}
```
