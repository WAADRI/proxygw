# Windows 服务安装说明（NSSM 或 sc.exe）

proxygw 的 server/client 都是标准控制台程序，可用 Windows 服务包装器注册为开机自启服务。

## 方式一：NSSM（推荐）

```powershell
# 1. 安装 NSSM：https://nssm.cc/download 解压后把 win64/nssm.exe 放到 PATH
# 2. 部署文件
New-Item -ItemType Directory -Force C:\proxygw
Copy-Item .\proxygw-client.exe C:\proxygw\
Copy-Item .\config.client.yaml C:\proxygw\
New-Item -ItemType Directory -Force C:\proxygw\state

# 3. 注册服务（客户端节点）
nssm install proxygw-client "C:\proxygw\proxygw-client.exe"
nssm set proxygw-client AppParameters "-config C:\proxygw\config.client.yaml"
nssm set proxygw-client AppDirectory "C:\proxygw"
nssm set proxygw-client AppStdout "C:\proxygw\client.log"
nssm set proxygw-client AppStderr "C:\proxygw\client.err.log"
nssm set proxygw-client Start SERVICE_AUTO_START
nssm start proxygw-client

# 服务端同理：nssm install proxygw-server ...
```

## 方式二：sc.exe

Windows 的服务控制管理器要求服务程序实现服务控制协议；proxygw 二进制是控制台程序，
直接 `sc create` 会得到 1053 错误。请使用 NSSM、WinSW 或“任务计划程序（开机触发、最高权限）”
来托管；不要使用 `sc create` 直接注册。

## 防火墙

- 服务端：放行 TCP 443（面板+wss）与 **UDP 443**（QUIC），以及代理入口端口 8080/1080。
- 客户端：**不需要**放行任何入站端口。

```powershell
New-NetFirewallRule -DisplayName "proxygw server tcp" -Direction Inbound -Protocol TCP -LocalPort 443,8080,1080 -Action Allow
New-NetFirewallRule -DisplayName "proxygw server udp" -Direction Inbound -Protocol UDP -LocalPort 443 -Action Allow
```

## 卸载

```powershell
nssm stop proxygw-client
nssm remove proxygw-client confirm
```
