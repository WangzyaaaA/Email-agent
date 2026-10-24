# AGENTS.md

本文件适用于整个仓库。后续 agent 在修改代码前应先阅读本文件与 `README.md`，并以这里的安全边界为最高优先级。

## 项目目标

Mail Sentinel 是运行在家庭 NAS 上的只读邮箱智能 Agent。当前首版已实现：

- QQ 邮箱、Gmail、阿里企业邮箱/钉邮和自定义 IMAP 接入。
- WxPusher，以及端到端加密的自建 Android FCM 验证码、重要邮件和期限提醒。
- 待回复跟踪，以及日、周、月摘要。
- FastAPI 中文局域网管理页面。
- SQLite 持久化、Docker Compose 部署和可选 OpenAI 兼容分类接口。
- 独立公网 Push Gateway、Android App、设备配对/吊销、可靠 ACK 与补偿同步。
- Android 本地密文库已升级到 schema v2，并使用短时处理租约协调 FCM 回调与补偿同步，避免并发重复解密和展示。
- Push Gateway 已建立 schema v1 版本基线、结构校验、WAL 一致备份和升级前自动备份流程。

不要把钉邮当作独立邮箱服务器。钉邮只是客户端；实时收件应连接阿里企业邮箱或该账号实际使用的 IMAP 服务商。

## 不可破坏的安全边界

以下约束属于产品要求，不得为了简化实现而绕过：

1. 邮箱操作必须严格只读。不得增加发送、删除、移动、归档、标记已读或修改 flags 的代码路径。
2. IMAP 目录必须以只读方式打开；读取正文必须使用 `BODY.PEEK`。优先读取 `BODYSTRUCTURE`，只下载有大小上限的文本 section。
3. 不下载或落盘附件。正文只允许在内存中处理，不得写入数据库、日志、审计记录或错误页面。
4. 不得记录邮箱密码、授权码、三方客户端安全密码、验证码、WxPusher Token、模型密钥或完整通知载荷。
5. 验证码长期只保存不可逆指纹和遮罩预览。完整码只可短期加密进入通知队列，并在发送成功或过期后清除。
6. 未知验证码来源只生成候选。只有经过批准的精确地址或域名才允许推送完整验证码。
7. SPF、DKIM 或 DMARC 明确失败时不得泄露完整验证码。只信任由已知接收服务器写入的最上层认证结果，不能信任发件人自行注入的认证头。
8. 发现邮箱域名时只能生成服务器建议。用户确认 IMAP 主机后，才可向该主机提交凭据。
9. 所有外部连接必须使用 TLS；IMAP 固定为 SSL 993，不提供明文回退。
10. 管理页面保持登录会话、CSRF 防护和安全 Cookie 配置。默认只面向局域网，不增加互联网公开入口或微信远程命令。
11. 管理员拒绝开放 IMAP 时应显示受限状态，不得使用浏览器模拟登录、抓取 Cookie 等绕过方式。
12. 自建推送不得为 NAS 增加公网入站接口。公网只能暴露独立 Push Gateway；网关不得连接邮箱、代理管理页或取得通知内容根密钥。
13. 通知标题、摘要和完整验证码进入网关前必须在 NAS 加密。网关与 FCM 只承载应用层密文；网关数据库还要使用网关主密钥做第二层静态加密。
14. Publisher、Device Admin、Device Bearer、设备 HMAC、FCM 登记标识、内容根密钥、消息信封和二维码内容不得进入日志、审计或错误响应。网关三类凭据必须保持作用域隔离。
15. 配对必须先由 NAS 在网关预配认证密钥，再显示一次性二维码；不得退化为只凭 Device Token 首次登记的 TOFU。设备请求必须校验 HMAC、时间戳、一次性 nonce 和单调 `registration_version`。
16. 选择主通知通道必须由管理员明确完成。通知入队时冻结通道；不得自动并行双发。只有 `otp`、`security` 和 `critical deadline` 可按既定快速失败规则一次性回退 WxPusher。
17. “网关已接受”“FCM 已接受”“设备 ACK”是三个不同状态。不得把 NAS 通知行的 `sent` 或 FCM message name 表述为手机已送达。
18. Android App 不得提供邮箱或 NAS 控制能力，不得维持自建 WSS 或永久前台服务。凭据必须由 Android Keystore 包装，私有数据排除在备份/迁移之外，生产连接只信任系统 CA 且禁止明文 HTTP。
19. 验证码和安全告警默认隐藏锁屏正文。只有用户显式开启敏感预览后才能展示；不得把完整验证码放入公共通知版本、action URI、日志或通知外的持久化字段。
20. ACK、过期、吊销或最终失败后按协议及时清除短期密文。吊销必须同时使旧 Device Token、设备认证密钥、FCM 登记标识和未确认网关信封失效。

任何可能改变上述行为的改动都需要在实现前明确指出风险，并增加针对性测试。

## 代码结构

- `app/main.py`：FastAPI 生命周期、页面路由、表单和管理接口。
- `app/config.py`：`EMAIL_AGENT_` 环境变量及启动安全检查。
- `app/models.py`：SQLAlchemy 核心模型和枚举。
- `app/database.py`：SQLite 引擎、WAL、外键与会话。
- `app/migrations.py`：现有 NAS SQLite 的 FCM 通知字段幂等升级、回滚和升级前备份命令。
- `app/security.py`：主密钥派生、Fernet 加密、HMAC 指纹、Argon2 密码和遮罩。
- `app/push_protocol.py`：跨 Python/Kotlin 的 HKDF、AAD、AES-GCM、base64url、请求签名和载荷上限规范。
- `app/store.py`：加密设置和审计写入。
- `app/mail/providers.py`：QQ、Gmail、Alibaba/DingMail、自定义 IMAP 预设及 MX/CNAME 识别。
- `app/mail/imap_source.py`：只读连接、目录发现、IDLE、轮询补偿、有限 MIME section 下载和连接错误分类。
- `app/mail/parser.py`：邮件头、正文、线程关系和认证结果解析。
- `app/services/detector.py`：验证码候选识别和误报排除。
- `app/services/classifier.py`：硬规则、脱敏和可选云模型分类。
- `app/services/pipeline.py`：邮件去重、分类、候选、通知和重试任务编排。
- `app/services/notifier.py`：WxPusher/FCM 通道路由冻结、可靠队列、夜间免打扰、重试和受限回退。
- `app/services/fcm_channel.py`：NAS 侧网关 HTTPS 客户端、配对材料、信封冻结和错误分类。
- `app/services/push_management.py`：设备吊销重试、本地最终清理和旧密钥信封失效处理。
- `app/services/actions.py`：截止日期与待回复提醒。
- `app/services/digests.py`：日周月摘要生成、幂等执行和加密快照。
- `app/services/monitor.py`：每个邮箱的监控线程生命周期。
- `app/services/maintenance.py`：数据留存和过期密文清理。
- `app/scheduler.py`：后台定时任务。
- `app/templates/`、`app/static/`：轻量中文管理页面。
- `push_gateway/`：独立 FastAPI 公网密文转发网关、作用域凭据、设备 API、FCM HTTP v1、队列与本地运维 CLI。
- `push_gateway/migrations.py`：网关 schema v1 基线、已有表结构校验、版本记录和带完整性检查的 SQLite 在线备份。
- `deploy/push-gateway/`：独立网关与 Nginx 通用 Compose、复用外部 Nginx 的独立适配版、代理安全边界、Secret 占位和运维说明。
- `android/`：API 26+ Kotlin App，包含 Keystore、FID 登记、FCM 接收、本地密文 SQLite v2、短时处理租约、隐私通知、WorkManager ACK/同步和 Gradle Wrapper。
- `protocol_vectors.json`：Python/Kotlin 共用的密码学黄金向量；修改协议时必须同步更新两端测试。
- `ANDROID_FCM_PUSH_DESIGN.md`：自建推送的完整安全设计、状态机、协议和验收矩阵。
- `tests/`：规则、解析器、IMAP、流水线、通知、摘要、推送协议、网关迁移/备份、运维状态和 Android 安全回归测试。

## 核心行为

### IMAP 同步

- 优先使用服务器声明的 IDLE；不可用或断线时每 30 秒轮询，每 5 分钟做 UID 补偿同步。
- 以账户、目录、UIDVALIDITY、UID 和 Message-ID 组合去重。
- checkpoint 只能推进到已完整处理的最高 UID；解析或处理失败时不能越过失败邮件。
- 首次同步回溯最近 7 天、每目录最多 500 封。历史邮件只建立基线，不补发旧验证码、旧重要提醒或旧期限提醒。
- 使用 IMAP `INTERNALDATE` 作为到达时间的优先依据。
- 自动识别收件箱、已发送、垃圾邮件、草稿、归档等目录属性，不依赖单一中英文目录名。

### 邮箱服务商

- QQ：`imap.qq.com:993`，使用邮箱授权码。
- Gmail：`imap.gmail.com:993`，首版使用应用专用密码，不含 OAuth。
- 阿里企业邮箱：默认 `imap.qiye.aliyun.com:993`，使用完整邮箱地址和三方客户端安全密码。
- 钉邮绑定第三方邮箱时使用 Custom IMAP，不得强制套用阿里服务器。
- 阿里认证失败信息应覆盖：管理员未放行第三方客户端、IMAP 未开启、安全密码错误、IP 白名单限制和普通网络/TLS/DNS 故障。

### 分类、通知和摘要

- 硬规则先识别 VIP、账号安全、付款异常、行程变化和 48 小时内到期事项。
- 云模型为可选增强。发送前必须去掉引用历史、签名、跟踪链接、附件信息，并遮盖验证码和各类凭据。
- `high`/`critical` 立即通知。22:30–07:30 延迟普通提醒，但验证码、安全告警和两小时内到期事项仍即时发送。
- 行动项状态为 `new / acknowledged / snoozed / done`；期限提前 24 小时与 2 小时提醒；期待回复的已发送邮件 3 天无回复时提醒一次。
- 摘要按北京时间每日 20:30、周日 20:30、每月最后一天 20:30 运行；同一时刻的多种摘要合并。
- 通知、处理任务和摘要必须可重试且幂等。不要移除现有唯一键、租约或进程内锁，除非用更强的机制替代。

### 自建 Android FCM 推送

- 默认主通道仍为 WxPusher；升级和创建配对都不能自动切换到 FCM。管理员必须在设备激活后显式切换。
- NAS 只主动连接规范化的 HTTPS 网关源站，不跟随重定向，不允许 userinfo、路径穿越或公网配置中的私网 IP。Loopback 仅可由独立测试配置开启。
- 每条通知只生成一次冻结的 AES-256-GCM 信封；正常重试复用相同 nonce、AAD 和 ciphertext。同一幂等键对应不同信封必须返回冲突。
- 网关持久化 `accepted / retry_wait / fcm_accepted / waiting_registration / acknowledged / expired / revoked / permanent_failed` 等状态，使用 `lease_until`、持久化重试时间和单进程锁恢复投递。
- FCM 只发送 data message。当前 Android SDK 使用 Firebase Installation ID（FID）的 `register` / `onRegistered`；首版 JSON 字段仍保留兼容名 `fcm_token`。
- App 先把消息 ID、有效期和端到端密文事务性落到私有 SQLite v2，再通过唯一 message ID 和原子短时 `claim_until` 租约取得处理权；只有租约持有者可以解密和显示通知。
- FCM 回调与 pending 同步发生竞争时，不得把“未取得租约”误判为已处理或发送 ACK；竞争方应延后重试，进程中断后由租约过期恢复处理。
- `onDeletedMessages`、网络恢复、启动和重启后使用有页数上限的 pending 同步补偿；不得通过高频轮询、自建长连接或前台服务补偿。
- App 报告 `shown`、`stored_notifications_disabled` 或 `expired` 后，网关清除消息信封。通知权限关闭、设备离线或未 ACK 不触发 NAS 的 WxPusher 回退。
- 配对、测试、通道切换和吊销均为管理写操作，必须使用 POST、登录会话、CSRF；创建配对和吊销还需管理员密码重新认证与明确确认。

## 数据与并发约束

- NAS 与 Push Gateway 各自使用独立 SQLite/WAL、进程、配置前缀、卷和容器镜像；生产部署各只支持一个应用实例和一个 Uvicorn worker。
- WxPusher 没有业务幂等键。进程在第三方接收后、本地提交前崩溃时可能重复一次；设计优先保证不漏告警。
- 正文、附件和明文验证码不得进入数据库。NAS 密钥、邮箱凭据、通知载荷、模型重试载荷、摘要快照、网关 Token 和内容根密钥使用 NAS `Cipher` 加密；网关敏感字段使用独立 `GatewayCipher` 加密。
- 网关只保存最小路由元数据、带密钥指纹、加密的设备认证密钥/FCM 登记标识和二次加密的端到端信封；不得保存 content root key 或通知明文。
- 元数据、摘要、行动项和通知默认保留 90 天；审计记录当前保留 30 天。
- NAS 启动会先执行 `Base.metadata.create_all()`，再运行 `app.migrations.upgrade_schema()`，当前只覆盖已文档化的 FCM 通知字段迁移。未来修改现有表必须同步扩展显式迁移、回滚、备份、模型、测试和 README；不得假设 `create_all()` 会修改旧表。
- Push Gateway 使用显式 schema 版本基线、结构校验和带完整性检查的 SQLite 备份命令。修改网关现有表时必须增加独立的版本迁移、升级前备份与恢复测试，不能假设 `create_all()` 会修改旧表，也不能删除数据库或卷完成升级。
- `gateway_schema_migrations` 只记录版本和应用时间，不得保存凭据或密文；运维升级使用 `python -m push_gateway.cli upgrade`，该命令必须在变更 schema 前生成并校验备份，单独备份使用 `python -m push_gateway.cli backup`。
- 网关运维统计必须与服务端真实状态名保持一致；`fcm_accepted` 只表示 FCM 已接受，在设备 ACK、过期或最终失败前仍属于待完成消息。
- Android 本地消息表当前为 schema v2，`claim_until` 只保存处理租约时间，不得保存通知明文；后续修改 schema 必须递增版本、实现非破坏性 `onUpgrade` 并保留已有密文与去重状态。
- 处理并发唯一冲突时使用 nested transaction/savepoint，不能因单封重复邮件回滚同批次其他工作。

## 开发约定

- Python 版本为 3.12 及以上；生产镜像使用 Python 3.12。
- 使用 SQLAlchemy 2.x 查询风格、带时区的 UTC 时间和 `zoneinfo` 进行北京时间转换。
- 新增配置放入 `app/config.py`，环境变量使用 `EMAIL_AGENT_` 前缀；敏感配置不得提供可用于生产的默认值。
- Push Gateway 配置放入 `push_gateway/config.py`，使用独立 `PUSH_GATEWAY_` 前缀。NAS 配置不得读取网关环境变量，网关也不得导入 NAS 的运行时配置或数据库会话。
- 新增持久化敏感字段前先判断是否确有必要；若必要，必须加密并定义清理期限。
- UI 保持服务端渲染、轻依赖和移动端可用。所有状态变更必须使用 POST 并校验 CSRF。
- 外部 HTTP 和 IMAP 调用必须设置超时、捕获可诊断错误，并通过本地队列或调度器重试；不得在请求线程中无限等待。
- 不要在异常消息、模板或审计详情中拼接原始正文与凭据。
- 保留用户已有配置和数据。不要在开发或测试中删除真实 `data/`、`.env` 或 Docker volume。
- 修改推送协议时，必须同步更新 `app/push_protocol.py`、Android Kotlin 实现、`protocol_vectors.json`、Python/Kotlin 测试和 `ANDROID_FCM_PUSH_DESIGN.md`。
- Android 当前使用 compile SDK 37.1、target SDK 36、min SDK 26、AGP 9.3.2 和 Gradle 9.5。不要把 Firebase 服务账号放进 App，也不要提交 Firebase 标识、release keystore 或签名密码。
- Android 消息处理顺序必须保持“密文持久化 → 取得处理租约 → 解密/展示 → 标记完成 → 异步 ACK”；任何改动都要覆盖并发竞争、租约过期恢复和旧 schema 升级测试。
- 当前 App 有意使用 FID `register` / `onRegistered`，`MailMessagingService` 上的 `MissingFirebaseInstanceTokenRefresh` 抑制由静态回归测试保护；除非同步修改登记协议、SDK 行为和两端测试，否则不要改回 token 刷新路径。
- Android 正式包只能使用用户离线保管的 release keystore。未配置 Firebase 项目标识或只生成 unsigned/debug APK 时，不得描述为可生产侧载包。

## 本地验证

安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[test,gateway]"
```

运行完整测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

附加检查：

```powershell
.\.venv\Scripts\python.exe -m compileall -q app push_gateway tests
.\.venv\Scripts\python.exe -m pip check
```

当前本地验证基线（2026-10-24）：

- Python 完整测试为 175 项通过（含依赖安全下限、登录限速、网关限速器内存上限与分块请求体上限回归）；`compileall`、`pip check` 与 `pip-audit` 通过。
- Python 依赖安全下限：`cryptography>=50.0.2`、`certifi>=2026.10.19`、`pillow>=13.0.0`、`pytest>=9.0.3`。`tests/test_repository_security.py` 会在这些下限被下调时失败。
- 管理台统一安全响应头（严格 CSP、`X-Frame-Options: DENY`、`nosniff`、`no-referrer`、HTML `no-store`），模板不得重新引入内联事件处理器。
- Android 依赖（OkHttp 5.5.0、zxing-android-embedded 4.3.0、AndroidX、Firebase BoM 34.18.0）的 OSV Maven 查询无已公开公告。
- Android `testDebugUnitTest`、Debug/Release 构建、Debug/Release Lint 和 `assembleDebugAndroidTest` 通过（2026-09-02 基线，本次未重跑）。
- Android Lint 当前为 0 个错误、11 个警告；未连接真机或模拟器，因此仪器测试只完成 APK 编译，未执行 `connectedDebugAndroidTest`。
- 当前未配置用户 Firebase 项目标识和 release keystore；Release 结果仅为 unsigned 构建验证，不是可生产侧载包。

修改以下区域时至少增加对应回归测试：

- OTP 正则、白名单或认证头信任逻辑。
- IMAP BODYSTRUCTURE、section 限制、checkpoint 或 UID 去重。
- 通知领取、重试、过期或夜间免打扰。
- 摘要周期、幂等键或加密快照。
- CSRF、会话、密码哈希、主密钥和敏感信息清理。
- 登录失败限速、安全响应头、CSP 与模板内联脚本边界。
- 网关请求限速器的内存上限与来源淘汰策略。
- MX/CNAME 服务商识别与阿里邮箱故障分类。
- 推送 HKDF/AAD/AES-GCM/HMAC、载荷上限、冻结信封和 Python/Kotlin 黄金向量。
- 网关凭据作用域、预配顺序、防重放、幂等冲突、FCM 错误分类、租约、ACK、清理和状态指标。
- 网关 schema 版本基线、已有数据保留、WAL 一致备份、完整性检查、不完整 schema 拒绝启动和运维状态名。
- FCM 主通道冻结、提交不确定性查询、紧急类别回退、吊销重试和旧密钥消息处理。
- SQLite 升级/回滚、旧数据保留、升级前备份和已有表字段补齐。
- Android Manifest 权限、系统 CA、备份排除、Keystore、FID 登记、本地密文 schema v1→v2、处理租约竞争/恢复、通知隐私与无邮箱控制接口。

Android 验证（需已安装相应 SDK；设备测试执行还需要物理设备或模拟器）：

```powershell
Set-Location android
.\gradlew.bat :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
.\gradlew.bat :app:assembleRelease :app:lintRelease :app:assembleDebugAndroidTest
```

未提供 release keystore 时 `assembleRelease` 只验证 unsigned release。`assembleDebugAndroidTest` 只证明仪器测试 APK 可编译；只有 `connectedDebugAndroidTest` 成功才可声称设备端测试已执行。

自动化测试不得连接真实邮箱、WxPusher、Firebase、公网 Push Gateway 或云模型；网关测试只能使用本地 TestClient、内存数据库和模拟 FCM。真实联调只能在用户明确提供测试账号/Token、Firebase 项目、公网域名与设备并确认目标服务器后执行，完成后不得把凭据、服务账号、签名密钥、测试数据库或配对二维码提交到仓库。

## 完成标准

提交改动前确认：

1. 保持严格只读邮箱边界。
2. 没有新增正文、附件、明文验证码或凭据持久化/日志泄露。
3. 新增写操作具有登录与 CSRF 防护。
4. 外部失败不会丢任务，重试不会正常情况下重复通知。
5. 首次历史同步不会补发旧提醒。
6. 相关测试已新增或更新，完整测试、编译和依赖检查通过。
7. 部署方式、环境变量、数据库结构或用户可见行为变化已同步到 `README.md`。
8. 推送改动保持 NAS 只出站、网关不见明文、Android 无管理能力，且三种接受/送达状态没有混淆。
9. ACK、过期、吊销和最终失败后的密文清理路径已验证；紧急回退类别没有扩大。
10. 若修改 Android，单元测试、Lint 和相关 APK 构建通过；没有真机时明确标注仪器测试仅完成编译。
11. 若修改 Android 消息接收或本地数据库，验证持久化先于解密/展示、并发处理只有一个租约持有者、租约过期可恢复且旧数据不丢失。
12. 若修改 Push Gateway 表结构或消息状态，提供版本迁移、升级前备份/恢复测试，并同步 CLI 统计、部署文档和状态语义。

## 已知限制与后续方向

- 尚未使用真实 QQ、Gmail、阿里企业邮箱和 WxPusher 凭据完成联调。
- 尚未使用用户自己的 Firebase 项目、公网域名和物理 Android 设备完成端到端推送联调，也没有用户正式签名的 release APK；当前仅完成 JVM 单元测试、静态安全回归、Lint、APK 构建和仪器测试 APK 编译。
- 首版仍只支持单台 Android 设备；FCM 可达性依赖设备上的 Google Play 服务与网络环境，目前没有真实设备送达时延或可靠性基线。
- Push Gateway 当前迁移能力是 schema v1 基线、结构校验和备份框架；尚无实际的 v1→v2 表结构迁移，首次新增或修改已有列时必须实现新版本迁移，不能把现有框架描述为通用自动迁移。
- 已在本地 WSL Docker 完成两种 Push Gateway Compose 配置解析与 Nginx 隔离代理验证；尚未完成真实公网部署或 Firebase 端到端联调。
- Gmail OAuth、阿里邮箱 MCP、钉钉机器人、日程/待办写入、回复草稿与发送均不在首版范围。
- 后续可增加账单/订单/快递/票务卡片、营销邮件聚合与退订建议、钓鱼和仿冒域名检测、语义搜索与附件 OCR。
- 任何发送邮件、写入钉钉日程/待办等功能都必须是独立的可选模块，并在每次外部写入前取得用户明确授权；不得改变当前默认只读模式。
