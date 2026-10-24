# 邮箱智能 Agent

一个运行在家中 NAS 的只读邮箱助手，支持 QQ 邮箱、Gmail、阿里企业邮箱/钉邮和自定义 IMAP。它可以识别白名单验证码、提醒重要邮件、跟踪截止日期与待回复事项，并通过 WxPusher 或端到端加密的自建 Android FCM 通道发送通知与日、周、月总结。

## 安全设计

- IMAP 目录始终以只读模式打开，读取使用 `BODY.PEEK`，不会改变已读状态。
- 先读取 `BODYSTRUCTURE`，只下载受限大小的文本 MIME section；附件不会下载到 NAS。
- 邮件正文仅在内存中处理。数据库保存元数据、脱敏摘要、待办和审计记录，默认 90 天清理。
- 邮件主题和发件人显示名在写入元数据前脱敏；标题中的验证码也不会以明文进入摘要或待回复事项。无 Message-ID 时的主题关联键使用不可逆指纹，通知中可复制的完整验证码仍只保留在短期加密载荷中。
- 邮箱密码、WxPusher Token、模型密钥和短期重试内容使用 NAS 主密钥加密。
- 验证码仅对白名单来源推送；成功发送或过期后立即删除通知密文，数据库只长期保留不可逆指纹和遮罩预览。
- 只信任已知邮箱服务商认证服务器写入的 SPF/DKIM/DMARC 结果，邮件自行伪造的 `Authentication-Results` 不会获得信任。
- 管理台必须登录且所有写操作都有 CSRF 防护。应用没有自动回信、删除、移动或标记邮件的代码路径。
- 管理台响应统一附加严格 CSP（禁止内联脚本、内联样式和第三方来源）、`X-Frame-Options: DENY`、`nosniff`、`no-referrer` 与 HTML `no-store`；交互脚本集中在 `app/static/app.js`，修改模板时不要重新引入内联事件处理器。
- 管理员登录按来源限速：同一来源连续 5 次密码错误后锁定 5 分钟，锁定期内不再执行 Argon2 校验，避免把登录接口当成无限次的密码猜测入口。

WxPusher 是第三方通知服务。完整验证码会短暂经过 WxPusher；只应为可信发件人建立白名单。自建 Android 通道会在 NAS 上加密标题、摘要和验证码，公网网关与 FCM 只看到应用层密文。

## NAS Docker 部署

1. 复制环境变量文件并生成随机主密钥：

   ```powershell
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

2. 把生成值填入 `.env` 的 `EMAIL_AGENT_MASTER_KEY`。主密钥丢失后，已保存的邮箱凭据无法恢复；请将它和数据库卷分别备份。

3. 启动：

   ```powershell
   docker compose up -d --build
   ```

4. 在局域网访问 `http://NAS地址:8080`，完成管理员和 WxPusher 首次配置，再添加邮箱。

Docker Compose 使用名为 `mail-sentinel-data` 的卷保存 SQLite 数据库。若需要从公网访问，必须在可信反向代理后启用 HTTPS，并设置 `EMAIL_AGENT_SECURE_COOKIES=true`；不建议直接暴露 8080 端口。

### 更新 WSL 测试实例

仓库根目录的 `update-wsl.sh` 用于更新独立的 `MailSentinel-Test` 测试实例。脚本会保留部署目录中的 `.env` 和 Docker 数据卷，并在同步代码前停止容器、复制卷内容、生成经过 SQLite 完整性检查的一致性备份。它只更新 NAS 应用，不会部署公网 Push Gateway 或自动切换通知主通道。

首次使用时，在测试 WSL 中安装 `rsync`，然后从部署目录运行脚本：

```bash
apt-get update
apt-get install -y rsync
cd /opt/mail-sentinel-test
./update-wsl.sh
```

脚本默认从 `/mnt/f/repos/email_agent` 读取最新版源码。若 Windows 仓库位于其他位置，可通过 `MAIL_SENTINEL_SOURCE_DIR` 指定对应的 WSL 挂载路径。升级备份保存在 `/opt/mail-sentinel-test/backups/pre-update-<UTC时间>/`。不要使用 `docker compose down -v`，否则会删除测试数据库卷。

## 邮箱准备

### QQ 邮箱

- 在 QQ 邮箱设置中开启 IMAP/SMTP。
- 生成独立授权码；添加邮箱时填写授权码，不要填写 QQ 密码。
- 服务器预设为 `imap.qq.com:993`。

### Gmail

- 开启 Google 两步验证并生成应用专用密码。
- 服务器预设为 `imap.gmail.com:993`。
- 部分单位账号、高级保护账号或仅使用安全密钥的账号可能无法生成应用密码；首版不含 Gmail OAuth。
- 认证失败与登录后的邮件同步失败会分别显示；若应用密码测试成功但提示同步失败，无需先重置密码，应检查服务器返回的 MIME section 兼容错误。

### 钉钉企业邮箱 / 阿里企业邮箱

钉邮是客户端，实际连接取决于底层邮箱服务。添加页面会先根据邮箱域名的 MX/CNAME 给出建议，用户确认服务器后才会提交凭据。

若底层为阿里企业邮箱：

- 请管理员在阿里邮箱域管理后台把该账号加入“三方客户端访问策略”例外。
- 为账号开启 IMAP，并生成“三方客户端安全密码”。
- 若企业启用了 IP 白名单，将 NAS 出口 IP 加入允许范围。
- 推荐服务器为 `imap.qiye.aliyun.com:993`；香港节点、旧版或自定义域名可手动覆盖。

若钉邮绑定的是其他企业邮箱，选择“自定义 IMAP”，并向管理员索取 SSL IMAP 地址。管理员无法开放 IMAP 时，应用会显示受限状态，不会通过浏览器模拟登录绕过策略。

## WxPusher 与模型

- 在 WxPusher 创建应用，取得 AppToken 和个人 UID，在设置页保存后使用“测试通知”。
- 云模型是可选项。填写 OpenAI 兼容的 HTTPS base URL、模型名和 API Key 后，先保存本地分类并将必要告警入队，再由后台任务补充分类；模型请求不会阻塞后续邮件和验证码处理。后台每 60 秒领取任务，首次请求和失败重试共用持久化队列。
- 模型地址不能包含账号密码、查询参数或片段；配置时和每次请求前都会检查，且不跟随重定向。升级前已保存的不安全地址会暂停云分类，设置页会提示重新配置，本地规则继续运行。
- 发给模型前会去掉引用历史、跟踪链接和附件，主题与正文都要遮盖验证码、密码、Bearer Token、JWT 与长随机凭据；模型返回的摘要和原因再次脱敏，错误记录只保存固定错误分类。
- 模型不可用时，本地硬规则继续工作；脱敏后的待分类内容最多加密保留 24 小时用于重试。本地安全分类不会被云模型改成普通类别，安全通知的隐私和受限回退语义保持不变。

## 自建 Android FCM 推送

该通道由三个独立组件组成：家庭 NAS 上的 Mail Sentinel、公网 HTTPS Push Gateway，以及装有 Google Play 服务的 Android App。NAS 只主动出站，不新增公网入口；网关没有邮箱连接、管理页或通知内容密钥；App 只负责配对、解密、去重和显示通知，不能控制邮箱或 NAS。

通知状态分为三个层次：

- NAS 记录“网关已接受”，只表示网关事务已持久化；
- 网关记录“FCM 已接受”，仍不代表手机已经显示；
- App 安全落地并显示通知（或发现通知权限关闭）后发送 ACK，网关随即清除消息密文。

正常路径只使用一个主通道，不并行双发。选择自建通道后，仅验证码、账号安全告警和 critical 两小时截止提醒可在网关快速失败三次后一次性回退到已配置的 WxPusher。鉴权、证书或请求格式错误不回退；手机离线、未 ACK 或通知权限关闭也不会触发回退。每条通知在入队时冻结通道，更改全局设置不会改变旧通知的路线。

### 升级已有 NAS 数据库

本版本会幂等增加通知路线和冻结信封字段，并新建 `push_devices` 表，不会删除旧通知或配置。升级前必须备份 SQLite 数据库或 Docker volume。可在停掉应用后使用带备份的升级命令：

```powershell
.\.venv\Scripts\python.exe -m app.migrations upgrade --database-url sqlite:///./data/mail_sentinel.db
```

命令会先在数据库旁创建带 UTC 时间戳的 `.bak` 文件。若尚未写入新字段，可用同样方式执行 `downgrade`；回滚应用前仍应保留升级前备份。应用启动也会执行同一套幂等升级，但不能代替升级前备份。不要通过删除数据库或 Docker volume 升级。

### 部署公网 Push Gateway

1. 准备独立域名，只把 TCP 443 指向该服务器。不要在同一域名代理 Mail Sentinel 管理页。
2. 在独立 Firebase 项目启用 FCM HTTP v1，为网关创建只具备发送消息权限的服务账号，将 JSON 保存为 `deploy/push-gateway/secrets/firebase-service-account.json`。该文件不是 Android 的 `google-services.json`，不得提交仓库。
3. 复制并填写网关环境文件：

   ```powershell
   Set-Location deploy\push-gateway
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

4. 选择 Nginx 部署方式：默认 `docker-compose.yml` 为通用独立部署，先设置 `PUSH_GATEWAY_DOMAIN`，并在 `PUSH_GATEWAY_TLS_DIR`（默认 `secrets/tls`）准备覆盖该域名的 `fullchain.pem` 和 `privkey.pem`，再启动：

   ```powershell
   docker compose run --rm --no-deps nginx nginx -t
   docker compose up -d --build
   ```

   Nginx 不自动签发/续期证书，续期后需检查配置并 reload。若服务器已有占用 80/443 的 Nginx，使用独立的 `docker-compose.external-nginx.yml`，不要同时启动默认版；该适配版只启动网关、接入已有 `nginx` 网络，配套 `nginx-mail.conf` 适用于现有 `mail.zonwe.top` 站点及证书挂载。完整步骤见 [Push Gateway 部署说明](deploy/push-gateway/README.md)。适配版后续所有 Compose 命令均须加 `-f docker-compose.external-nginx.yml`。

5. 只在网关主机本地初始化两类 NAS Token。它们只显示一次：

   ```powershell
   docker compose run --rm gateway python -m push_gateway.cli init
   ```

   `publisher` 只能发布和查询幂等状态；`device_admin` 只能预配、查询激活和吊销设备。轮换时使用 `python -m push_gateway.cli rotate publisher` 或 `rotate device_admin`，先验证新 Token，再用 `list` 查看旧凭据 ID，并以 `revoke <credential_id>` 停用旧版本。CLI 会拒绝停用某作用域的最后一个有效凭据。

网关数据库使用显式 schema 版本基线。升级网关镜像前先停止网关应用，再运行 `docker compose run --rm gateway python -m push_gateway.cli upgrade`；命令会使用 SQLite 在线备份接口生成包含 WAL 已提交数据的一致性备份、执行完整性检查并输出 schema 版本。也可使用 `python -m push_gateway.cli backup` 单独生成经过检查的备份。不要通过删除数据库或 volume 完成升级。

网关容器使用独立 SQLite 卷、非 root 用户、只读根文件系统和最小 capabilities。主密钥、Firebase 服务账号与数据库备份必须分开保存。ACK、过期或吊销会立即清除消息信封；无内容状态保留 7 天，防重放 nonce 只保留签名接受窗口。公网不启用 OpenAPI 文档。

网关对每个来源按分钟限速（默认 120 次），限速表按来源有上限并定期清理，攻击者轮换 IPv6 地址不会让内存无限增长；请求体在读取阶段就按 `PUSH_GATEWAY_MAX_REQUEST_BYTES`（默认 16 KiB）拒绝超限请求，缺少 `Content-Length` 的分块请求同样受限，不会先整体缓冲再判断。

反向代理访问日志只保存时间、状态码、字节数和耗时，不得记录 Authorization、设备签名、nonce、原始 URI 或请求/响应体；请求级原始错误日志关闭。`deploy/push-gateway/nginx-gateway.conf.template` 和 `nginx-mail.conf` 包含上述边界、16 KiB 请求上限及转发头覆盖规则。网关应用端口不映射到公网，两版均保留原 `gateway-data` 卷；切换部署方式时保持原 Compose project name，且不得删除旧数据库、主密钥或卷。

### NAS 配置、配对与吊销

1. 在局域网管理页打开“Android 推送”，填写规范的 `https://` 网关源站，以及离线命令生成的 Publisher Token 和 Device Admin Token。
2. 重新输入管理员密码创建配对。NAS 会先在网关预配设备认证密钥，成功后才显示十分钟有效的一次性二维码。
3. 用 Android App 扫描二维码。二维码包含完整设备凭据，只显示一次，页面使用 `no-store`、严格 CSP 和 `no-referrer`。
4. App 完成 FCM 登记标识（当前 SDK 使用 FID）登记后，在 NAS 页点“刷新网关状态”确认设备为 `active`，再明确选择“自建 Android FCM”为后续通知主通道。该按钮对已激活设备同样可用，用于发现网关侧被吊销或登记失效后 NAS 页面仍显示旧状态的情况。
5. 丢失设备时，在同一页面重新输入管理员密码并确认吊销。NAS 会立即停用旧通道；网关离线时后台持续重试，确认后才删除 NAS 上的内容根密钥。

配对、测试、通道切换和吊销都是登录后的 POST 操作并校验 CSRF。Android 没有这些管理接口。

### 构建 Android App

项目位于 `android/`，使用 API 37.1 编译、目标 API 36、最低 API 26，并使用 Firebase Android BoM 34.18.0。编译 SDK 与目标 SDK 分离，使依赖获得当前平台 API 与安全修复，同时不在缺少物理设备回归时贸然启用 Android 17 的目标行为。App 不使用自建 WSS、永久前台服务、analytics 或崩溃上报，也不申请通讯录、短信、存储、悬浮窗或辅助功能权限。

Firebase 配置支持以下两种方式，选择一种即可喵：

- 将 Firebase 控制台下载的 Android 客户端配置保存为 `android/app/google-services.json`，包名必须为 `com.mailsentinel.push`，构建时会自动启用 Google Services 插件喵。
- 没有该文件时，仍可在用户自己的 `~/.gradle/gradle.properties`（不要提交）中填写下面的 Firebase Android 公共项目标识喵。

`google-services.json` 已被 Git 和 Docker 构建上下文忽略，不要强制提交，也不要用网关的 Firebase 服务账号私钥 JSON 代替它喵。

```properties
MAIL_SENTINEL_FIREBASE_API_KEY=...
MAIL_SENTINEL_FIREBASE_APPLICATION_ID=...
MAIL_SENTINEL_FIREBASE_PROJECT_ID=...
MAIL_SENTINEL_FIREBASE_SENDER_ID=...
```

在仓库根目录运行以下命令，生成用于安装验证的 Debug APK 喵：

```powershell
Set-Location android
.\gradlew.bat :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

产物位于 `android/app/build/outputs/apk/debug/app-debug.apk`，是测试包而非正式签名发布包；更换 Firebase 配置后必须重新构建并安装喵。

正式侧载包必须使用用户离线保管的 release keystore。通过 Gradle 用户配置或 CI Secret 提供以下属性/环境变量，路径不得位于仓库：

```text
MAIL_SENTINEL_KEYSTORE_FILE
MAIL_SENTINEL_KEYSTORE_PASSWORD
MAIL_SENTINEL_KEY_ALIAS
MAIL_SENTINEL_KEY_PASSWORD
```

配置好正式签名后，在 `android/` 目录运行 `.\gradlew.bat :app:assembleRelease :app:lintRelease` 喵。

未提供签名配置时只生成未签名 release 产物，不能视为正式发布包。debug APK、测试 Firebase 项目和测试网关不得复用生产凭据。

App 使用 Android Keystore 中不可导出的 AES 包装密钥加密 content root key、device token 和 FCM 登记标识；当前 Firebase SDK 使用 FID 模式（`register` / `onRegistered`），不调用已弃用的 Token 获取接口。私有凭据、密文数据库和去重记录全部排除在 Auto Backup 与设备迁移之外。本地密文表以 message ID 唯一约束和短处理租约协调 FCM 接收与 pending 同步；同一消息只有取得租约的任务可以解密和展示，任务中断后可在租约过期时恢复。Android 13+ 会在解释用途后请求通知权限。验证码与安全告警默认使用锁屏隐藏的敏感通知；用户可显式开启预览，但通知历史、截图和辅助功能风险会增加。

App 只在网关确认过该设备激活之后才拉取通知：`pending_activation` 窗口内网关返回独立的 `device_not_activated`，App 按暂时性失败重试并继续完成登记，绝不会因为未激活而删除本地配对。只有在网关确认吊销（`invalid_device_credentials` 等，且该设备此前已激活）或用户手动清除时，才会删除本地配对密钥与密文。界面会显示“网关登记：已完成/等待完成”和最近一次网关稳定错误码，便于定位。

### 网关故障排查

- `gateway_authentication_failed`：Publisher Token 不匹配或已停用；不会回退。
- `tls_validation_failed` / `redirect_rejected`：证书、主机名或网关 URL 配置不安全；不会忽略证书，也不会携带凭据跟随重定向。
- `device_unavailable`：设备尚未激活或 FCM 登记标识已失效。未过期密文仍可由 App 的 pending 同步补偿。
- `submission_uncertain`：POST 结果不确定且状态查询也不可达；紧急类别最终可能受限回退，并接受极少数跨通道重复，由 App message ID 去重。
- App 显示“通知权限受限”：打开系统总通知权限和三个通知渠道。网关已接受但 App 权限关闭不能触发 WxPusher 回退。
- App 显示“网关登记：等待完成”：这是激活窗口的正常状态，网关返回 `device_not_activated`。打开 App 等待登记完成，或在 NAS 页点“刷新网关状态”确认；该状态不会删除配对。
- App 显示“设备未配对”而 NAS 仍显示 `active`：两侧状态分叉。NAS 页面只在“刷新网关状态”时同步网关真实状态；若网关已吊销或配对过期，刷新后即可重新配对。
- NAS 页面显示“网关最近状态：`waiting_registration`”：网关当前没有可用的 FCM 登记（例如 FCM 报告旧登记失效）。打开 App 完成重新登记后再发测试通知。
- App 首页“最近网关响应”：直接显示网关返回的稳定错误码，用于区分网络、鉴权、激活和吊销问题，不含任何载荷或凭据。

真实联调必须由用户提供自己的 Firebase 项目、公网域名和测试设备。自动化测试不连接真实 Firebase、邮箱、WxPusher 或云模型。

## 默认行为

- 验证码未知来源先进入候选列表；批准邮箱地址或域名后，后续验证码才会推送。
- 高优先级与严重告警立即发送。22:30–07:30 延迟普通通知；验证码、安全告警和两小时内到期事项不受影响。
- 截止日期提前 24 小时和 2 小时提醒；首次发现时已进入两小时窗口，只生成两小时提醒，不再倒序补发“明日到期”。24 小时提醒在进入两小时窗口后失效，已过期事项不再发送临期提醒；已发送的请求 3 天未收到线程回复时仍提醒一次。
- 北京时间每日 20:30、周日 20:30、每月最后一天 20:30 发送总结；同一时间的多个总结会合并。
- 首次连接只回溯最近 7 天、每目录最多 500 封，且不会补发历史验证码或历史重要提醒。
- IMAP 必需的邮件头、BODYSTRUCTURE 或文本 section 缺失时，当前批次失败重试，不推进 checkpoint，也不把失败的首次回溯转换为实时通知；确实返回的空文本 section 仍视为有效空正文。
- 连接状态、错误信息和同步时间更新不会重启邮箱监控；连接配置变化才替换监控线程，手动同步通过现有线程触发，通常在当前 IDLE/轮询等待结束后执行。

## 本地开发与测试

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[test,gateway]"
$env:EMAIL_AGENT_MASTER_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
.\.venv\Scripts\python.exe -m app
```

运行测试：

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m compileall -q app push_gateway tests
.\.venv\Scripts\python.exe -m pip check
```

自动化测试不会连接真实邮箱或 WxPusher。真实连接需要在管理台由用户确认服务器并提供授权码后测试。

### 依赖安全基线

用 `pip-audit` 复核已安装环境（只查询公开漏洞库，不连接真实业务服务）：

```powershell
.\.venv\Scripts\python.exe -m pip install pip-audit
.\.venv\Scripts\python.exe -m pip_audit
```

`pyproject.toml` 里的下限用于阻止重新安装已知受影响的版本，当前基线（2026-10-24）：

| 依赖 | 下限 | 修复内容 |
| --- | --- | --- |
| `cryptography` | 50.0.2 | openSSL/证书链验证与 PKCS#7 解密侧信道等 4 项公告，同时更换旧 wheel 内置的 OpenSSL |
| `certifi` | 2026.10.19 | 移除私钥已泄露的 eMudhra 中间 CA 信任链 |
| `pillow` | 13.0.0 | 13.0.0 之前的多项图像编解码越界与解压缩炸弹绕过 |
| `pytest` | 9.0.3（仅测试依赖） | 可预测的 `/tmp/pytest-of-{user}` 目录权限问题 |

不要为了让旧代码"零改动"把 `cryptography` 上限压回 `<47` 一类区间，那会静默安装带已知漏洞的版本；`tests/test_repository_security.py` 会在下限被回退时失败。本地以可编辑方式安装的本项目不在 PyPI 上，`pip-audit` 会把它列在跳过项里，这不影响其余依赖的审计结果。

Android 依赖用 OSV 的 Maven 生态逐项核对：2026-10-24 对 OkHttp 5.5.0、zxing-android-embedded 4.3.0、AndroidX、Firebase BoM 34.18.0 及测试库的查询均无已公开的 Maven 安全公告。

## 运维注意事项

- NAS 与公网网关都使用各自的单个应用实例和单个 Uvicorn worker；两者使用独立进程、配置前缀、数据库、卷和容器镜像。
- WxPusher 的 HTTP 接口不提供业务幂等键。极端情况下，如果进程在第三方已接收消息、但本地提交状态前崩溃，租约恢复可能造成一次重复通知，系统优先保证不漏告警。
- 修改主密钥前应先在管理台重新准备所有外部凭据；直接更换会使旧密文无法解密。
- 主题脱敏对后续处理的邮件生效；旧版已保存的元数据和既有备份不会因升级自动改写，应按原有数据留存及备份策略管理。此次加固不修改数据库表结构。
- NAS 数据库对已文档化的 FCM 字段使用显式、幂等迁移；Push Gateway 使用版本化 schema 基线、结构校验和带完整性检查的 SQLite 备份命令，未来修改已有网关表时仍必须增加对应版本迁移。两侧升级前都应备份对应数据库或 Docker volume。
