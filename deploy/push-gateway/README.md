# Push Gateway 运维清单

该目录只部署公网密文转发网关，不得代理 Mail Sentinel 管理页。

## 选择部署方式

| 场景 | Compose 文件 | HTTPS 入口 |
| --- | --- | --- |
| 通用、独立服务器 | `docker-compose.yml` | 本项目启动独立 Nginx，宿主机 TCP 443 → 容器 8443 |
| 已有 Nginx 和外部 `nginx` 网络 | `docker-compose.external-nginx.yml` | 复用已有 Nginx，本项目不发布宿主机端口 |

两份文件是独立方案，不能通过两个 `-f` 合并，也不要同时启动。两版均保留 `gateway-data` 卷和单实例网关；切换时应在同一部署目录保持原 Compose project name（包括原有 `-p` / `COMPOSE_PROJECT_NAME`），避免连接到新的空卷。网关仅在容器网络监听 8090。NAS 和 Android 只接受公网 HTTPS 443，不能通过改用公网 8443 解决已有 443 占用。

## 共用准备

1. 在本目录复制 `.env.example` 为 `.env`，生成随机 `PUSH_GATEWAY_MASTER_KEY`，填写 Firebase project ID；已有部署保留原主密钥和 `.env`。
2. 把最小权限 Firebase 服务账号只读放到 `secrets/firebase-service-account.json`。
3. 为网关准备专用域名和有效的公开信任证书，不要在该域名代理 NAS 管理页。

## 通用版：独立 Nginx

此方式要求宿主机 TCP 443 空闲，无需预先创建 Docker 网络。在 `.env` 设置 `PUSH_GATEWAY_DOMAIN`，填写纯域名，不带 `https://`、端口或路径。

将覆盖该域名的完整证书链和私钥放到 `secrets/tls/fullchain.pem`、`secrets/tls/privkey.pem`；也可通过 `PUSH_GATEWAY_TLS_DIR` 指定其他证书目录，但其中仍须使用这两个文件名。证书目录必须已存在，私钥限制为 root 可读且不提交仓库。挂载整个目录而非单个文件，便于续期时替换；目录内不能是指向容器不可见位置的符号链接。

Nginx 不负责自动申请或续期证书；通过宿主机 ACME 客户端的 DNS-01 等方式管理证书，更新两个文件后执行配置检查和 reload。公网只开放 TCP 443，不发布 HTTP 80、UDP 443 或网关 8090。

```bash
docker compose config --quiet
docker compose run --rm --no-deps nginx nginx -t
docker compose up -d --build
docker compose run --rm gateway python -m push_gateway.cli init
```

最后的 `init` 只在首次部署执行，将一次性显示的 Publisher / Device Admin Token 导入 NAS。NAS 网关地址填写 `https://你的网关域名`。

证书续期后：

```bash
docker compose exec nginx nginx -t && docker compose exec nginx nginx -s reload
```

`nginx.conf` 让临时文件仅使用 tmpfs；官方镜像只替换站点模板中的 `PUSH_GATEWAY_DOMAIN`，保留 `$host`、`$request_uri` 等 Nginx 变量。master 进程以 root 读取私钥，worker 切换到 nginx 用户，根文件系统只读且仅保留初始化 worker/临时目录所需的 CHOWN、SETUID、SETGID capabilities。

## 适配版：现有 nginx 网络与 mail.zonwe.top

这份方案适配已有容器 `nginx`、外部网络 `nginx`、`/home/bwg/nginx_conf/sites-enabled` 和 `/etc/nginx/ssl` 证书挂载。已有 Nginx Compose 不用修改。本项目仅启动 `gateway`，通过网络别名 `mail-sentinel-push-gateway:8090` 连接。

所有本项目 Compose 命令都必须带 `-f docker-compose.external-nginx.yml`，包括启动、初始化、状态查询、停止、升级和备份。此模式不使用 `.env` 中的 `PUSH_GATEWAY_DOMAIN` / `PUSH_GATEWAY_TLS_DIR`；域名和证书路径由现有 Nginx 站点文件控制。

```bash
sudo docker network inspect nginx
sudo docker compose -f docker-compose.external-nginx.yml config --quiet
sudo docker compose -f docker-compose.external-nginx.yml up -d --build
```

`nginx-mail.conf` 是完整的站点示例，应在主 `nginx.conf` 的 `http {}` 中 include，不能代替主配置文件。它将 `mail.zonwe.top` 从现有的 `photoranking:5000` 切换到 Push Gateway；如需保留该域名原用途，应另选专用域名并修改示例。已有证书必须实际覆盖 `mail.zonwe.top` 或 `*.zonwe.top`，仅有 `zonwe.top` 不够。

在本目录运行以下命令，先备份站点配置到 include 目录之外，再安装示例；如果 `sites-enabled/mail` 是符号链接，备份也会保存其原始内容：

```bash
mkdir -p /home/bwg/nginx_conf/backups
cp -L /home/bwg/nginx_conf/sites-enabled/mail /home/bwg/nginx_conf/backups/mail.$(date +%Y%m%d-%H%M%S)
cp nginx-mail.conf /home/bwg/nginx_conf/sites-enabled/mail
sudo docker exec nginx nginx -t && sudo docker exec nginx nginx -s reload
```

配置检查失败时不要 reload，修正配置或把备份内容复制回原路径。不要在 `sites-enabled` 留下 `mail.bak` 等备份，通配 include 可能同时加载它们。证书续期后同样需要执行 `nginx -t` 和 reload。

首次初始化并检查公开健康接口：

```bash
sudo docker compose -f docker-compose.external-nginx.yml run --rm gateway python -m push_gateway.cli init
curl --fail --show-error https://mail.zonwe.top/healthz
```

NAS 填写 `https://mail.zonwe.top`。保留原站点的 HTTP → HTTPS 跳转，但 NAS 和 App 必须直接使用 HTTPS，不依赖带凭据重定向。

共享网络中的 OpenList、MeTube 等容器也能访问 8090，网关凭据鉴权仍然必需；只把受信任容器接入此网络。需要进一步隔离时，应为 Nginx 与网关另建专用网络。

## 日志与反向代理边界

两份站点配置均设置 16 KiB 请求上限、有限超时、禁用请求/响应磁盘缓存，并原样转发签名覆盖的路径和查询参数。入口使用 `$remote_addr` 覆盖 `X-Forwarded-For`，不能改回 `$proxy_add_x_forwarded_for`，否则客户端可伪造网关限速使用的来源地址；已有主配置也不得无条件信任公网客户端的 real-IP 头。

访问日志只允许时间、状态码、字节数和耗时，不记录原始 URI、查询参数、任何请求头或请求/响应体。请求级原始错误日志丢弃，避免 Nginx 将异常请求行或认证头写入日志；通过 `nginx -t`、HTTP 状态、安全访问日志和网关 CLI 排查故障。不要为网关站点启用 debug、请求转储或第三方完整请求日志。通用版访问日志输出到容器 stdout；适配版输出到 `/var/log/nginx/mail-sentinel-access.log`，应配置短期保留和轮转。

## 升级与备份

从旧版 Caddy 迁移时，先按旧部署方式停止该项目的 Caddy，避免继续占用 443；保留原数据库卷、主密钥和证书备份。删除仓库中的 Caddy 配置不会删除服务器上的旧容器或卷。不要使用 `docker compose down -v` 或 volume prune。

升级镜像前先停止 `gateway` 服务，再运行 `docker compose run --rm gateway python -m push_gateway.cli upgrade`。该命令会在数据库卷内生成包含 WAL 已提交数据的一致性备份、执行 SQLite 完整性检查并记录当前 schema 版本；确认输出后再启动新网关。只需要备份时可运行 `python -m push_gateway.cli backup`。不要通过删除数据库或 volume 升级。

适配版对应命令：

```bash
sudo docker compose -f docker-compose.external-nginx.yml stop gateway
sudo docker compose -f docker-compose.external-nginx.yml build gateway
sudo docker compose -f docker-compose.external-nginx.yml run --rm gateway python -m push_gateway.cli upgrade
sudo docker compose -f docker-compose.external-nginx.yml up -d gateway
sudo docker compose -f docker-compose.external-nginx.yml run --rm gateway python -m push_gateway.cli backup
sudo docker compose -f docker-compose.external-nginx.yml run --rm gateway python -m push_gateway.cli status
```

定期做 SQLite 一致性快照，并把加密备份、网关 master key 和 Firebase Secret 分开保存。恢复演练后运行清理任务，确认 ACK、过期和吊销消息的旧密文没有重新进入投递队列。

本机监控可周期运行 `docker compose run --rm gateway python -m push_gateway.cli status`。输出只含设备/消息状态计数、最老待投递年龄和最近 24 小时稳定错误码计数，不含设备标识、Token、密文或通知内容；应对持续 `fcm_permission_denied`、`fcm_service_unavailable`、`fcm_token_unregistered` 和队列年龄超阈值告警。

不要把 `.env`、服务账号、数据库、备份、Token 或 TLS 私钥提交仓库。证书续期失败、FCM 401/403、持续 5xx、无效设备 Token和队列老化需要通过服务器本地监控告警；告警只记录稳定错误码。
