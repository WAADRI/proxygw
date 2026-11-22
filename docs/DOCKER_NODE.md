# 节点侧 Docker 部署指南

节点（client）**主动外连**服务端，不需要任何入站端口；宿主机只需允许出站 `TCP/443`（wss）与 `UDP/443`（QUIC），容器本身不需要 `-p` 端口映射。

本文以示例服务端 `https://gw.example.com:443` 为例，请替换为实际地址。

## 1. 获取镜像

### 1.1 直接使用 GHCR 预构建镜像（推荐）

GitHub Actions 会为每次 main 构建多架构镜像（linux/amd64 + linux/arm64）：

- `ghcr.io/waadri/proxygw-client`
- `ghcr.io/waadri/proxygw-server`

可用 tag：`latest`、`main`、`sha-<commit>`；推送 `v*` tag 时还会生成对应的版本 tag（如 `v1.0.5`）。

镜像已公开（GHCR Public），可直接匿名拉取，无需 `docker login`：

```bash
docker pull ghcr.io/waadri/proxygw-client:latest
```

下文的 `docker run` 命令直接使用 `ghcr.io/waadri/proxygw-client:latest`，无需本地构建。

### 1.2 从源码构建（可选）

```bash
git clone https://github.com/WAADRI/proxygw.git
cd proxygw

# 国内网络可指定 Go 模块代理
docker build -f deploy/Dockerfile.client \
  --build-arg VERSION=dev \
  --build-arg GOPROXY=https://goproxy.cn,direct \
  -t proxygw-client:dev .
```

镜像特性：多阶段静态编译、`alpine` 运行、非 root（`proxygw` 用户）、内置「环境变量优先」的默认配置、`/var/lib/proxygw/state` 声明为卷。

## 2. 单节点：docker run

镜像内置了「环境变量优先」的默认配置（`deploy/config.client.docker.yaml`），
只要给全 `SERVER_URL` / `AUTH_TOKEN` / `CLIENT_ID` 即可运行：

```bash
docker run -d \
  --name proxygw-node-1 \
  --restart unless-stopped \
  -e SERVER_URL=https://gw.example.com:443 \
  -e AUTH_TOKEN='<节点接入令牌>' \
  -e CLIENT_ID=node-docker-1 \
  -e ALIAS='Docker 节点 1' \
  -e TAGS='docker,test' \
  -e TRANSPORT=auto \
  -e PLANES=2 \
  -e COMPRESSION=true \
  -e TLS_MODE=ca \
  -e LOG_LEVEL=info \
  -v proxygw-node-1-state:/var/lib/proxygw/state \
  ghcr.io/waadri/proxygw-client:latest
```

查看日志（看到 `会话注册成功，进入 ready`、`"transport":"quic"` 即成功）：

```bash
docker logs -f proxygw-node-1
```

> 使用本地构建的镜像时，把最后的镜像名换成 `proxygw-client:dev` 即可。

## 3. 一台机器加多个节点

关键点：**每个节点唯一 `CLIENT_ID`，各自独立 state 卷**；令牌按服务端配置复用或每节点独立：

```bash
for i in 1 2 3; do
  docker run -d \
    --name "proxygw-node-$i" \
    --restart unless-stopped \
    -e SERVER_URL=https://gw.example.com:443 \
    -e AUTH_TOKEN='<节点接入令牌>' \
    -e CLIENT_ID="node-docker-$i" \
    -e ALIAS="Docker 节点 $i" \
    -e TAGS='docker,test' \
    -e TRANSPORT=auto -e PLANES=2 -e COMPRESSION=true -e TLS_MODE=ca \
    -v "proxygw-node-$i-state:/var/lib/proxygw/state" \
    ghcr.io/waadri/proxygw-client:latest
done
```

同一台机器/同一出口 IP 的多个节点在面板里会显示相同出口 IP（`egress_ip` 相同），
调度仍会把它们当作独立节点使用；需要真实多地区出口时请部署到不同机器/VPS。

## 4. 用 docker compose 管理

`deploy/docker-compose.client.yml` 默认直接使用 GHCR 镜像：

```bash
cp deploy/.env.client.example deploy/.env.client
# 编辑 deploy/.env.client：SERVER_URL / AUTH_TOKEN / CLIENT_ID / ALIAS / TAGS / TAG
docker compose -f deploy/docker-compose.client.yml --env-file deploy/.env.client up -d
docker compose -f deploy/docker-compose.client.yml --env-file deploy/.env.client logs -f
```

一机多节点用不同项目名（`-p`）+ 不同 env 文件：

```bash
docker compose -f deploy/docker-compose.client.yml -p node-1 --env-file .env.node1 up -d
docker compose -f deploy/docker-compose.client.yml -p node-2 --env-file .env.node2 up -d
```

需要从源码构建时，在 compose 文件中取消 `build:` 注释并使用 `--build`。

## 5. 配置项（环境变量）

| 环境变量 | 含义 | 示例/默认 |
|---|---|---|
| `SERVER_URL` | 服务端地址（同一个 443 端口 UDP=QUIC、TCP=wss） | `https://gw.example.com:443` |
| `AUTH_TOKEN` | 节点接入令牌 | 由服务端配置或管理面板签发 |
| `CLIENT_ID` | 节点唯一 ID，`[A-Za-z0-9_.:-]`，1–64 字符 | `node-docker-1` |
| `ALIAS` / `TAGS` / `REGION` | 面板显示名/标签/地区（逗号分隔） | `Docker 节点 1` / `docker,test` |
| `TRANSPORT` | `auto`（QUIC 优先，2s 回退 wss）/ `quic` / `ws` | `auto` |
| `PLANES` | 隧道平面数（1–8） | `2` |
| `COMPRESSION` | 是否声明支持 zstd | `true` |
| `STATE_DIR` | 节点 ID、TOFU pin 等状态目录 | 容器内 `/var/lib/proxygw/state` |
| `TLS_MODE` | `ca`（公共 CA 证书）/ `pin`（SPKI 指纹） | 服务端使用公共证书时用 `ca` |
| `TLS_PIN` / `TLS_PINS` | pin 模式下的当前/下一枚 SPKI 指纹 | pin 模式必填 |
| `TLS_CA_FILE` | 私有 CA 文件路径 | 默认用系统根证书 |
| `TLS_SERVER_NAME` | 覆盖 SNI/证书校验名 | 连接地址与证书 SAN 不一致时使用 |
| `LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info` |
| `EGRESS_IP` / `EGRESS_IP6` | 手动指定出口 IP（覆盖自动探测） | 可选 |

## 6. 验证节点是否接入成功

1. 容器日志：`docker logs proxygw-node-1 | grep -E "session.ready|HELLO 注册成功"`
2. 管理面板节点列表：应看到 `node-docker-1` 在线，transport 为 `quic`（或 `ws`），planes=2；
3. 面板节点详情里点「拨测/Ping」应返回 pong；
4. 需要精准验证时，可给节点打 `TAGS=docker,test`，在面板创建只匹配该标签的节点组与凭据，再用 HTTP/SOCKS5 代理访问外网，确认 TopN 中该节点计数增长。

## 7. 常见问题

| 现象 | 原因/处理 |
|---|---|
| `服务端拒绝注册：authentication failed`，容器反复重启 | 令牌不对/被吊销；确认 `AUTH_TOKEN`，或服务端是否启用了每节点令牌绑定 |
| 日志报 pin 不匹配 | 服务端用 pin 模式时需设置 `TLS_MODE=pin` + `TLS_PIN=sha256/...`；服务端用公共 CA 时保持 `TLS_MODE=ca` |
| 日志显示 QUIC 连接超时并回退 wss | 当前网络 UDP/443 被拦截；`auto` 会自动回退，可把 `TRANSPORT=ws` 固定为 wss |
| 容器启动即退出，提示 `STATE_DIR` 不可写 | 使用命名卷（如示例）或把宿主目录 `chown` 给容器内 uid；不要用 root 拥有的 bind mount |
| 时间不同步/时钟偏移告警 | 容器与宿主机需 NTP；时钟偏移过大时服务端会拒绝注册 |
| 面板出现重复出口 IP 提示 | 同一台机器跑多个节点属正常现象；真实多地区出口需部署到不同 VPS |
| 拉取 GHCR 镜像 401/denied | 包可能被设为私有或触发匿名拉取限制：确认包可见性为 Public，或临时 `docker login ghcr.io`（PAT 需 `read:packages`） |

## 8. 安全建议

- 不要把真实令牌写进镜像或提交到仓库；生产用 env-file（权限 600）或 Docker secrets 注入。
- 保持非 root、`no-new-privileges`；可再加 `--read-only` + `--tmpfs /tmp`（state 卷单独可写）。
- 容器不需要任何入站端口，不要加 `-p` 映射。
- 生产环境建议每节点独立令牌（服务端 `nodes.tokens` 配置）或启用 mTLS，而不是共享令牌。
- 升级：重新拉取新 tag → `docker rm -f` + 重新 `docker run`（state 卷保留，节点 ID 不变）；或 compose `up -d` 拉取新镜像。
