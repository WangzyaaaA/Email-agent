# Push Gateway 运维清单

该目录只部署公网密文转发网关，不得代理 Mail Sentinel 管理页。

1. 复制 `.env.example` 为 `.env`，生成随机 `PUSH_GATEWAY_MASTER_KEY`，填写独立域名与 Firebase project ID。
2. 把最小权限 Firebase 服务账号只读放到 `secrets/firebase-service-account.json`。
3. 运行 `docker compose up -d --build`，公网只开放 443。
4. 运行 `docker compose run --rm gateway python -m push_gateway.cli init`，立即把一次性显示的两个 Token 导入 NAS。
5. 定期做 SQLite 一致性快照，并把加密备份、网关 master key 和 Firebase Secret 分开保存。
6. 恢复演练后运行清理任务，确认 ACK、过期和吊销消息的旧密文没有重新进入投递队列。

升级镜像前先停止 `gateway` 服务，再运行 `docker compose run --rm gateway python -m push_gateway.cli upgrade`。该命令会在数据库卷内生成包含 WAL 已提交数据的一致性备份、执行 SQLite 完整性检查并记录当前 schema 版本；确认输出后再启动新网关。只需要备份时可运行 `python -m push_gateway.cli backup`。不要通过删除数据库或 volume 升级。

本机监控可周期运行 `docker compose run --rm gateway python -m push_gateway.cli status`。输出只含设备/消息状态计数、最老待投递年龄和最近 24 小时稳定错误码计数，不含设备标识、Token、密文或通知内容；应对持续 `fcm_permission_denied`、`fcm_service_unavailable`、`fcm_token_unregistered` 和队列年龄超阈值告警。

不要把 `.env`、服务账号、数据库、备份、Token 或 TLS 私钥提交仓库。证书续期失败、FCM 401/403、持续 5xx、无效设备 Token和队列老化需要通过服务器本地监控告警；告警只记录稳定错误码。
