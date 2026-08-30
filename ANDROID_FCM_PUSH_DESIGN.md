# Mail Sentinel 自建 Android FCM 推送设计

状态：已实施；真实 Firebase、域名和物理设备联调待用户凭据<br>
最后修订：2026-08-30<br>
目标平台：装有且可正常使用 Google Play 服务的 Android 设备<br>
部署形态：家庭 NAS + 独立公网 Push Gateway + Firebase Cloud Messaging（FCM）

本文使用“必须 / 不得”表示安全或正确性要求，使用“建议”表示首版可以调整的实现选择。

术语说明：FCM 已在 2026 年转向以 Firebase Installation ID（FID）登记和定向投递。本文早期章节中的“FCM Token”统指 FCM 设备登记标识；当前 Android 实现启用 FID 模式，使用 `register` / `onRegistered`，不再调用已弃用的 `getToken` / `onNewToken`。为保持首版网关协议兼容，`POST /v1/devices/register` 的 JSON 字段仍名为 `fcm_token`，其值在当前 App 中是 FID；该值仍按同等敏感级别加密、禁止记录并支持单调版本轮换。

## 1. 决策摘要

采用“NAS 只出站、公网网关只转发应用层密文、Android 本地解密”的结构：

```text
家庭 NAS：Mail Sentinel
        │
        │ HTTPS；只主动提交应用层密文
        ▼
公网服务器：Push Gateway
        │
        │ FCM data message；内容仍是应用层密文
        ▼
Google Play 服务
        │
        │ 系统调度与唤醒
        ▼
Android App：校验、解密、去重并显示系统通知
```

核心结论：

- NAS 保存邮箱凭据并执行现有只读邮件监控，不开放新的公网入口。
- 公网网关不连接邮箱、不持有通知内容密钥、不提供管理页面。
- FCM 只承载 data message；标题、摘要和验证码在进入网关前已经加密。
- Android 不维持自建 WSS 长连接，不运行永久前台服务。
- FCM 接受消息只表示“已进入 FCM 投递系统”，不表示设备已经收到；设备回执必须单独建模。
- 推送通道不增加任何邮箱写操作，也不允许 Android 远程修改 Mail Sentinel 配置。

这三个组件属于同一产品和同一代码仓库，但 NAS 服务与公网网关必须使用独立进程、依赖、配置前缀、数据库和容器镜像。即使以后把 Mail Sentinel 与网关部署到同一台服务器，也只能公开网关 API；管理页面仍只允许通过局域网、可信 VPN 或固定来源访问。

## 2. 范围与非目标

### 2.1 设计目标

1. 验证码、账号安全告警和两小时内到期事项在手机休眠时尽快送达。
2. 普通重要邮件和摘要允许受 Android Doze 调度影响，以降低耗电。
3. 邮件标题、摘要和完整验证码不以明文经过网关或 FCM，也不进入网关日志。
4. NAS、网关、FCM 或 App 短暂离线后，未过期消息能够重试或补偿同步。
5. 正常重试不重复显示通知；无法消除的极端重复必须被明确记录并由 App 去重。
6. 保持 Mail Sentinel 现有的只读邮箱、安全认证、验证码白名单和敏感数据清理边界。
7. 丢失设备能够从局域网管理页吊销，吊销后旧凭据无法继续登记、同步或确认消息。

### 2.2 非目标

- 不通过 App 发送、删除、移动、归档邮件，不标记已读或修改 IMAP flags。
- 不提供远程配置邮箱、批准验证码白名单、控制 NAS 或访问管理页面的能力。
- 不承诺电信级实时投递，也不把 FCM 的“已接受”当作端到端送达证明。
- 首版只支持一个 Android 设备，不实现群组、主题推送或跨用户共享。
- 首版不提供长摘要的远程阅读页；超长摘要在 NAS 侧生成安全截断版本。
- 不通过浏览器模拟登录、抓取 Cookie 或绕过邮箱管理员策略。

## 3. 信任边界与威胁模型

### 3.1 受保护资产

- 邮箱凭据、Mail Sentinel 主密钥和邮件处理数据；
- 通知明文，尤其是完整验证码、账号安全告警和邮件摘要；
- Android 设备内容根密钥、设备访问令牌和 FCM 注册 Token；
- 网关发布凭据、设备管理凭据、Firebase 服务账号凭据和网关主密钥。

### 3.2 信任假设

- 家庭 NAS、局域网管理会话和 Android 系统未被攻击者完全控制。
- Android 设备未 root，App 安装包未被替换，系统锁屏与 Android Keystore 正常工作。
- NAS 与 App 正确校验证书链、主机名和 HTTPS 地址，不信任用户安装的调试 CA 作为生产信任根。
- 网关可以被视为“不可信传输与存储节点”：读取网关数据库或 FCM 载荷的攻击者不应得到通知明文。

### 3.3 明确不覆盖的风险

- 攻击者控制 NAS、取得 Mail Sentinel 主密钥，或控制已解锁/root 的手机后，可以取得通知明文。
- 被攻陷的网关可以观察设备标识、优先级、大小、时间和投递状态，也可以延迟、丢弃或重放密文；端到端加密只保护机密性和完整性，不保证可用性。
- FCM、Android 厂商系统、网络运营商或用户设置可能延迟或阻止消息。
- 系统通知、通知历史、截图和辅助功能属于 Android 设备侧的展示边界。敏感通知默认隐藏锁屏正文，但用户主动降低系统隐私设置后仍可能暴露内容。
- 独立第三方通道之间无法实现严格的 exactly-once。发生“网关已接收但 NAS 未收到响应”等不确定故障时，受限回退可能造成一次跨通道重复，设计优先避免漏掉紧急告警。

## 4. 系统不变量

实施和评审时必须持续满足：

1. Mail Sentinel 的 IMAP 路径仍严格只读，推送功能不得引入邮箱写操作。
2. 邮件原始正文和附件不得进入网关、Android 本地数据库、日志、审计记录或错误页面。
3. 只有现有流水线已经批准推送的精简通知内容才可进入新通道；验证码白名单和认证头信任规则不得下移到网关或 App。
4. 网关永远不得取得设备内容根密钥或消息加密密钥。
5. 所有外部连接必须使用 TLS。生产 App 和 NAS 不提供忽略证书错误或明文 HTTP 的开关。
6. 配对、测试、吊销和通道切换都是管理状态变更，必须由已登录的局域网页面通过 POST、CSRF 校验和明确确认完成。
7. Token、密钥、nonce、ciphertext、FCM Token、完整请求载荷和通知明文不得出现在日志或审计详情中。
8. 消息过期、确认、吊销或最终失败后，必须按本文定义清除各处短期密文。

## 5. 组件职责

### 5.1 家庭 NAS：Mail Sentinel

- 复用现有 IMAP 只读监控、分类、验证码白名单、夜间免打扰和通知 outbox。
- 新增可选主通道 `fcm_gateway`；默认仍保持现有 WxPusher 行为，升级不得自动切换通道。
- 通知入队时冻结主通道。发送器不能因为当前配置后来变化而把旧通知静默改投另一通道。
- 在本地解开现有 `payload_encrypted` 后，将 HTML 通知转换为受限的纯文本结构，再使用设备消息密钥加密。
- 对同一通知和设备只生成一次 FCM 加密信封；重试必须复用完全相同的 nonce、AAD 和 ciphertext，避免 AES-GCM nonce 复用风险与幂等冲突。
- 通过 HTTPS 提交消息 ID、设备 ID、密钥版本、优先级、有效期和密文。网关明确持久化成功后，才把本地第三方提交记为成功。
- “网关已接受”沿用当前通知行 `sent` 的第三方提交语义，但不得在 UI 中表述为“手机已送达”。设备回执状态由网关单独维护。
- 夜间免打扰继续在 NAS 入队时统一判定。普通通知延迟到 07:30 后提交；验证码、账号安全告警和两小时内到期事项绕过免打扰。
- 网关地址必须是规范化的 `https://` URL，不允许 URL userinfo、fragment、非默认路径穿越或运行时重定向到其他主机。开发测试只能通过单独的测试配置允许 loopback 地址。

#### 主通道与受限回退

- 管理页在 WxPusher 与自建通道中选择一个主通道；正常路径不并行双发。
- 自建通道为主时，只有以下通知允许一次性回退到已配置的 WxPusher：
  - `kind=otp`；
  - `kind=security`；
  - `kind=deadline` 且 `priority=critical`，即现有两小时提醒。
- 建议快速失败窗口为首次尝试后 60 秒内最多 3 次，但只对 DNS、连接、TLS 握手中断、读取超时、网关 `429/5xx` 或明确的设备不可用错误计数；鉴权失败、请求格式错误、证书链或主机名校验失败属于配置/安全错误，立即告警，不盲目重试。
- POST 响应不确定时，NAS 先调用只返回元数据的幂等状态查询。网关确认已接收则不得回退；确认不存在才可回退。网关整体不可达且无法消除不确定性时，紧急通知可以回退，但必须接受极少数跨通道重复的可能。
- 一旦任一通道明确接受，通知行终结，另一通道不得再发送。回退原因只记录枚举错误码，不记录 URL、响应正文或通知内容。
- 设备侧未 ACK、用户关闭通知权限或手机离线都不能触发 WxPusher 回退；NAS 不具备可靠端到端送达信息。

### 5.2 公网服务器：Push Gateway

- 只提供版本化 JSON API、`healthz` 和必要的后台任务，不提供登录页或远程管理页面。
- 分别校验 NAS 发布令牌、NAS 设备管理令牌和 Android 设备凭据，作用域不得混用。
- 按业务幂等键接收并保存冻结的加密信封。同一幂等键与完全相同的信封重复提交时返回原结果；同一键对应不同元数据或密文时返回 `409 idempotency_conflict`。
- 使用网关主密钥加密保存 FCM Token、设备请求认证密钥和已是端到端密文的消息信封，形成静态存储的第二层保护。
- 调用 FCM HTTP v1 API，并区分“网关已接收”“FCM 已接受”“设备已确认”三个状态。
- 管理 OAuth 2.0 访问令牌：使用官方 Google Auth 库，令牌只在内存缓存，到期前刷新，并发刷新使用单飞锁；服务账号文件、访问令牌及完整 FCM 请求响应不得写日志。
- 对临时 FCM 错误在消息有效期内有限重试；对无效 FCM Token 停止发送并等待 App 重新登记。
- 接收 App 回执。只有 App 报告消息已安全落地并成功创建通知，或已安全落地但系统权限关闭，才删除网关消息密文。
- 消息过期或设备吊销时立即删除相应密文。状态元数据可短期保留用于去重和诊断。
- 不持有邮箱账号、IMAP 密码、邮件正文、设备内容根密钥、消息加密密钥或 NAS 管理 Cookie。

### 5.3 Android App

- 使用 `FirebaseMessagingService` 接收 FCM data message，不创建 WSS 长连接或永久前台服务。
- Android 13 及以上在解释用途后请求 `POST_NOTIFICATIONS`；权限未授予时明确显示受限状态和系统设置入口。
- 使用 Android Keystore 生成不可导出的 AES 包装密钥；设备内容根密钥和设备访问令牌以该密钥加密后存放在 App 私有存储，而不是假设任意外部生成的原始密钥都能直接导入 Keystore。
- 将凭据、本地消息密文和去重数据库排除在 Auto Backup、云备份和设备迁移之外。重装、清除数据或 Keystore 密钥失效后必须重新配对。
- 校验外层字段、设备 ID、密钥版本、有效期和 AES-GCM 标签，再解析严格限长的内部结构；任何校验失败都不得显示部分内容。
- 使用消息 ID 唯一约束做本地去重。先在单个本地事务中保存消息 ID、有效期和必要的端到端密文，再创建系统通知，最后异步提交回执。
- `onMessageReceived` 只执行有上限的校验、解密和通知创建。网络回执失败后交给 WorkManager：高优先级消息使用紧接接收回调创建的 expedited work，普通消息使用普通 work。
- `onRegistered`、App 启动、`onDeletedMessages` 和网络恢复时触发受限登记或补偿同步；不得高频轮询。App 启用 `firebase_messaging_installation_id_enabled`，登记值使用 FID。
- 首版不声明 `directBootAware`，设备重启后必须等用户首次解锁才能使用 App 私有凭据；首次解锁后立即执行一次补偿同步。
- App 只提供配对、连接/权限状态、测试通知、通知展示和本机清理，不提供任何邮箱或 NAS 控制接口。

#### 设备侧隐私显示

- 建立至少三个通知渠道：验证码/安全、重要邮件、摘要。FCM 传输优先级与 Android 通知渠道重要性是两个不同概念，不能混用。
- 验证码和账号安全告警默认使用敏感模式：锁屏和屏幕共享时只显示通用提示，解锁后才显示具体内容；不得把验证码放入 ticker、快捷回复、公共版本或通知 action URI。
- 提供明确的便利性选项，允许用户主动开启敏感内容预览，但默认关闭，并提示 Android 通知历史、截图和辅助功能可能保留或读取内容。
- App 本地只保存端到端密文和最小元数据。用户查看、通知过期或吊销后清除密文；去重 ID 可在不含内容的情况下保留“最大消息 TTL + 7 天”。

## 6. 凭据、派生密钥与配对

首版单设备仍使用每设备独立凭据，为未来多设备保留 `device_id` 和 `key_id`。

### 6.1 凭据类别

| 凭据 | 持有方 | 作用域 | 网关保存方式 |
| --- | --- | --- | --- |
| `gateway master key` | 网关 | 加密网关敏感字段、生成令牌指纹 | 不进入数据库；Secret 注入 |
| `publisher token` | NAS、网关 | 发布消息、查询本发布者的幂等状态 | 只保存带密钥指纹 |
| `device admin token` | NAS、网关 | 预配和吊销设备；不能发布或读取消息 | 只保存带密钥指纹 |
| `device token` | Android、网关 | 标识设备并作为第一层 Bearer 凭据 | 只保存带密钥指纹 |
| `content root key` | NAS、Android | 派生消息密钥和设备请求认证密钥 | 网关永不保存 |
| Firebase 服务账号 | 网关 | 获取短期 OAuth 令牌并调用 FCM | 只读 Secret 文件或工作负载身份 |

所有随机 Token 和 `content root key` 使用密码学安全随机数生成器产生至少 256 位熵，不使用用户密码。高熵 Token 的服务端校验采用网关主密钥 HMAC 指纹和恒定时间比较，不在数据库保存原文。

网关首次初始化通过离线管理命令生成 publisher token 与 device admin token，只显示一次；管理员在局域网管理页分别导入 NAS。该初始化命令只能在网关主机本地运行，不实现公网“创建 Token”接口。轮换任一 Token 时先增加新版本、验证 NAS 已切换，再吊销旧版本，避免把消息队列锁死。

### 6.2 密钥派生

以 32 字节 `content root key` 为输入，使用 HKDF-SHA-256，`salt` 为规范化 `device_id`，按 `info` 域分离派生：

```text
message_key = HKDF(root, salt=UTF8(device_id), info="mail-sentinel/android/message/v1", length=32)
device_auth_key = HKDF(root, salt=UTF8(device_id), info="mail-sentinel/android/device-auth/v1", length=32)
```

- `message_key` 只存在于 NAS 与 Android，用于 AES-256-GCM。
- NAS 在显示二维码前通过设备预配接口把 `device_auth_key` 交给网关；网关用 master key 加密保存它，只用于校验设备 HMAC，无法由它反推 `message_key` 或根密钥。
- 使用对称设备 HMAC 意味着被完全攻陷的网关能够伪造设备 API 请求，但网关本来就能删除或阻断密文；它仍不能解密或伪造能通过 AES-GCM 的通知内容。若未来需要抵抗恶意网关伪造设备身份，可把设备认证升级为独立签名密钥对。

### 6.3 无抢注窗口的配对流程

不得采用“App 首次登记时把认证密钥交给网关”的 TOFU 流程；仅泄露 `device token` 的攻击者会在真设备之前抢注自己的 FCM Token。首版必须先预配、后展示二维码：

1. 管理员在局域网管理页重新验证管理员密码，提交带 CSRF 的“创建配对”POST。
2. NAS 生成 `device_id`、`key_id`、`device token` 和 `content root key`，并派生 `device_auth_key`。
3. NAS 使用独立 `device admin token` 调用 `POST /v1/devices/provision`。网关保存 device token 指纹、加密的认证密钥和十分钟激活期限，状态为 `pending_activation`。
4. 网关预配成功后，NAS 才展示一次性二维码。二维码包含：
   - 配置版本；
   - 规范化的网关 HTTPS 地址；
   - `device_id` 与 `key_id`；
   - `device token`；
   - `content root key`；
   - 配对过期时间。
5. App 扫描后校验版本、HTTPS 和过期时间，保存凭据，使用已经预配的 `device_auth_key` 对首次 FCM Token 登记请求签名。
6. 网关验证 Bearer、HMAC、时间戳、nonce 和激活期限后将设备置为 `active`。过期且未激活的记录与认证密钥立即删除。
7. NAS 收到激活状态后启用自建通道。若激活失败，保持原通道不变，不允许半配置状态发送真实通知。

二维码等同完整设备凭据，必须满足：

- 只在已登录、重新认证并通过 CSRF 的局域网页面生成；
- 响应使用 `Cache-Control: no-store`、严格 CSP、`Referrer-Policy: no-referrer`，不写日志和审计详情；
- 页面离开后不重新显示。失败或过期时废弃整组凭据并重新生成；
- NAS 只短期保存待展示的 device token；激活后保留 `device_id`、`key_id`、content root key 和所需网关凭据的加密值，不需要长期保存 device token 原文。

### 6.4 设备请求签名与防重放

设备接口同时要求 `Authorization: Bearer <device token>` 和 HMAC 请求签名。建议头部：

```text
X-MS-Timestamp: Unix 秒
X-MS-Nonce: 16 字节随机值的 base64url
X-MS-Signature: HMAC-SHA256 的 base64url
```

签名输入使用固定 UTF-8 编码和换行分隔：

```text
v1
HTTP_METHOD
规范化路径与查询字符串
SHA256(原始请求体字节)
X-MS-Timestamp
X-MS-Nonce
```

网关必须：

- 限制时间偏差，例如正负 5 分钟；
- 在接受窗口内按设备保存已使用 nonce，重复 nonce 返回 `409 replay_detected`；
- 对 FCM Token 登记额外要求单调递增的 `registration_version`，拒绝旧版本覆盖新 Token；
- 对路径、查询、请求体和 Content-Type 采用唯一规范，跨 Python/Kotlin 使用固定测试向量验证；
- 在鉴权完成前执行严格请求体大小和速率限制。

### 6.5 吊销与轮换

- 吊销只能由局域网管理页重新认证、CSRF 校验和二次确认后发起。NAS 使用 `device admin token` 调用网关吊销接口；Android 无权触发或阻止吊销。
- 网关把设备置为 `revoked`，删除 FCM Token、认证密钥和全部未确认密文，并拒绝旧 device token 的登记、同步和回执。
- NAS 只有在网关确认吊销后才删除本地 content root key；网关暂时不可达时本地先停用通道并持续重试吊销，不能恢复使用旧设备。
- 重新配对必须生成全新的 device token、content root key 和 key ID。旧密钥不允许续配。
- 吊销或轮换时，本地尚未提交的旧 key ID 信封必须作废；符合回退条件的紧急通知可重新从现有 NAS 加密载荷生成新路线，其他通知标记为需要管理员处理，不得用已吊销密钥继续发送。

## 7. 通知密文与 FCM 载荷

### 7.1 内部明文结构

Android 通道不直接发送现有 HTML。NAS 应先生成严格限长的 UTF-8 JSON：

```json
{
  "schema": 1,
  "kind": "otp",
  "title": "示例服务验证码",
  "body": "验证码 123456，预计 10 分钟内有效",
  "created_at": "2030-01-01T00:00:00Z",
  "sensitive": true
}
```

- 字段采用 allowlist，拒绝未知类型、嵌套 HTML、链接 action、图片和附件。
- 标题、正文、字段数和 UTF-8 总字节数都必须单独限长；首版建议内部明文不超过 2200 字节。
- 超限内容必须在 NAS 加密前按字符边界安全截断并增加固定提示，不得把剩余正文上传到网关作为可远程读取的长内容。

### 7.2 加密信封

每个设备使用派生的 `message_key` 做 AES-256-GCM：

- nonce 必须是 CSPRNG 生成的 96 位随机值，并在同一 key ID 下保证不复用；
- 认证标签使用 128 位；
- AAD 是下列字段的固定规范化编码：`version`、`message_id`、`device_id`、`key_id`、`priority`、`expires_at`；
- `expires_at` 使用 UTC RFC 3339 秒精度和 `Z`，不得由网关延长；
- 同一通知重试复用已经冻结的整个信封，不重新加密；
- Android 在解密前先校验外层字段格式和上限，解密后再次校验内部 `kind` 与安全显示策略。

AAD 首版固定为下列 UTF-8 字节，末尾不加换行；标识符只允许无换行的 UUID 或 base64url，`priority` 只允许 `normal/high`，时间必须使用规范 UTC 格式：

```text
v1
<message_id>
<device_id>
<key_id>
<priority>
<expires_at>
```

所有二进制字段统一使用无 `=` padding 的 base64url。协议实现不得依赖 JSON 对象键顺序来生成 AAD。

FCM 的 `data` 值均为字符串，建议信封如下：

```json
{
  "version": "1",
  "message_id": "opaque-id",
  "device_id": "device-id",
  "key_id": "key-id",
  "priority": "high",
  "expires_at": "2030-01-01T00:00:00Z",
  "nonce": "base64url-nonce",
  "ciphertext": "base64url-ciphertext-and-tag"
}
```

FCM data message 最大载荷为 4096 字节。实现不得只检查明文字数；必须对最终 `message.data` 序列化后的 UTF-8 字节数做测试并预留协议开销，建议硬上限 3500 字节。超限在 NAS 侧失败并生成安全截断版本，网关不得静默丢字段。

### 7.3 优先级、有效期与折叠

| 消息类型 | FCM 传输优先级 | 最大有效期 | Android 展示 |
| --- | --- | --- | --- |
| 验证码 | high | 10 分钟，且不超过流水线计算的验证码有效期 | 敏感渠道；过期不显示 |
| 账号安全告警 | high | 24 小时 | 敏感渠道 |
| 两小时内到期事项 | high | 距截止时间的剩余时长，且最长 2 小时 | 高重要性渠道 |
| 普通重要邮件 | normal；明确需要即时交互时才用 high | 24 小时 | 默认渠道 |
| 日、周、月摘要 | normal | 48 小时 | 低打扰渠道 |

- 网关每次调用 FCM 时计算 `ttl = max(0, expires_at - now)`，不得使用 FCM 默认四周 TTL。
- 已过期消息不调用 FCM 并立即清除密文；App 也必须独立拒绝过期消息，不能只相信网关。
- 首版所有实际通知使用 non-collapsible data message，因为每条都有独立内容。FCM 不保证顺序，App 不能依赖到达顺序。
- Android 对单设备可缓存的非折叠消息数量有限；触发 `onDeletedMessages` 时必须做分页补偿同步。
- 高优先级必须确实产生用户可见通知。若用户关闭通知权限，App 应通过设备状态接口上报受限状态，避免长期发送不会显示的 high 消息导致 FCM 降级。

## 8. 数据流与状态机

### 8.1 正常投递

1. Mail Sentinel 识别出需要通知的事件，完成验证码来源和邮件认证安全检查。
2. 现有 outbox 生成本地业务 `dedupe_key`、有效期和 NAS 主密钥加密载荷。
3. 发送器冻结 `channel=fcm_gateway`，生成随机且不透明的网关幂等键、设备消息 ID、纯文本结构和一次性 AES-GCM 信封，并把幂等键与冻结信封再次用 NAS `Cipher` 加密保存。现有可能带类型或本地主键的 `dedupe_key` 不直接发送到公网。
4. NAS 调用 `POST /v1/messages`；请求携带发布凭据和业务幂等键，不携带现有管理会话 Cookie。
5. 网关在一个事务中校验幂等性、保存密文并返回稳定 `gateway_message_id`。
6. 网关调用 FCM HTTP v1。FCM 返回 message name 后，网关记录 `fcm_accepted`；这仍不是设备送达证明。
7. Google Play 服务把 data message 交给 App。
8. App 校验、解密、去重，把必要密文和消息 ID 安全落地，创建系统通知。
9. App 使用 WorkManager 可靠提交 `POST /v1/messages/{id}/ack`。
10. 网关记录回执并立即删除消息密文；只保留短期无内容状态用于幂等和诊断。

### 8.2 NAS 通知状态

建议在现有 `notifications` 表显式增加以下字段或引入一对一 delivery 表，不得把状态编码进 `last_error`：

- `channel`：`wxpusher | fcm_gateway`；
- `route`：`primary | fallback_wxpusher`；
- `route_attempts` 与 `first_route_attempt_at`；
- `wire_envelope_encrypted`：冻结的 FCM 信封，使用 NAS `Cipher` 再加密；
- `gateway_message_id` 或复用明确扩容后的 `external_id`；
- `fallback_reason_code`：仅枚举值。

状态转换：

```text
pending
  ├─ 到期 ───────────────► expired（清除全部内容密文）
  ├─ 网关明确接受 ───────► sent（清除 NAS 内容与 wire 密文）
  ├─ 可回退且满足规则 ───► pending / fallback_wxpusher
  └─ 可重试失败 ─────────► failed → pending
```

现有 SQLite 只使用 `Base.metadata.create_all()`，不会自动为旧表增加字段。实施此设计时必须同时提供可回滚的 schema 升级方案和回归测试；发布说明必须要求现有部署先备份数据卷。不得通过删除旧数据库完成升级。

### 8.3 网关消息状态

```text
accepted
  ├─ FCM 2xx ─────────────► fcm_accepted
  ├─ 临时错误 ────────────► retry_wait ─► accepted
  ├─ 无效 FCM Token ──────► waiting_registration
  ├─ 设备有效回执 ────────► acknowledged（立即清除密文）
  └─ 到期/吊销 ───────────► expired/revoked（立即清除密文）
```

- `POST /v1/messages` 的成功只要求网关事务已提交；响应必须返回当前状态，不能伪称设备已送达。
- FCM 请求超时可能处于“服务端已接受但网关未收到响应”的不确定状态。网关重试完全相同的 FCM data message，App 依靠 message ID 去重。
- App 回执 `result` 建议为：`shown`、`stored_notifications_disabled`、`expired`、`decrypt_failed`。前三者可清除密文；`decrypt_failed` 保留到过期并触发无敏感内容的配置告警。
- ACK 丢失时网关可能再次推送；App 发现本地 message ID 已存在后只补发 ACK，不再次显示。

### 8.4 断线补偿

- NAS 到网关失败：指数退避加抖动；紧急类别按第 5.1 节执行一次性回退。
- 网关到 FCM 失败：按第 10 节分类，在原有效期内重试。
- App 离线：依赖 FCM TTL；重新上线后接收仍有效消息。
- FCM 删除积压或队列溢出：`onDeletedMessages` 触发受限分页同步。
- App 被强行停止：Android 不保证继续接收；用户重新打开 App 后重新登记 FCM Token 并执行补偿同步。
- 通知权限关闭：App 仍可安全保存已收到密文并返回受限回执，但必须在首页持续提示；开启权限后只补显示仍未过期且尚未显示的本地消息。

## 9. 网关 API 草案

| 方法与路径 | 调用方 | 凭据 | 用途 |
| --- | --- | --- | --- |
| `GET /healthz` | 监控 | 无 | 只返回通用存活状态 |
| `POST /v1/devices/provision` | NAS 管理流程 | device admin token | 预配设备认证材料 |
| `POST /v1/devices/{id}/revoke` | NAS 管理流程 | device admin token | 吊销设备 |
| `GET /v1/devices/{id}/activation` | NAS 管理流程 | device admin token | 查询是否完成激活 |
| `POST /v1/devices/register` | Android | device token + HMAC | 首次登记或轮换 FCM Token |
| `POST /v1/devices/status` | Android | device token + HMAC | 上报通知权限等有限能力状态 |
| `POST /v1/messages` | NAS | publisher token | 幂等提交冻结信封 |
| `GET /v1/messages/status` | NAS | publisher token | 按幂等键消除提交不确定性 |
| `GET /v1/messages/pending` | Android | device token + HMAC | 分页读取本设备未确认密文 |
| `POST /v1/messages/{id}/ack` | Android | device token + HMAC | 提交本地处理结果 |

共同约束：

- 只接受 HTTPS 和 `application/json`。HTTP API 直接拒绝，不通过重定向转发带 Authorization 的请求。
- 每种 Token 只能访问表中对应作用域。publisher token 不能预配/吊销设备，device admin token 不能发布或读消息，device token 不能跨设备访问。
- 统一限制请求体、字段长度、设备/发布者速率、时间戳偏差、nonce 重放、分页大小和最大有效期。
- `pending` 只返回当前设备、未过期、未确认的密文，每页建议不超过 50 条，并使用不泄露数据库主键的游标。
- `status` 只返回幂等键对应的存在性、状态、网关消息 ID 和时间，不返回 FCM Token、ciphertext 或设备认证信息。
- 设备状态只接受 allowlist 字段，例如通知总权限、渠道可用性和 App 协议版本；不得上传设备名称、账号、通讯录或广告标识。
- 响应和异常不得回显 Authorization、FCM Token、认证密钥、nonce、ciphertext 或通知内容。请求验证错误使用稳定枚举码。
- 反向代理来源头只在请求确实来自受信代理时使用，避免伪造客户端 IP 或限速键。
- OpenAPI 文档默认不在公网启用；若保留，仅在构建时生成静态内部文档。

## 10. FCM 调用与错误分类

网关使用 FCM HTTP v1 API。建议使用官方 Google Auth 库获取短期 OAuth 2.0 令牌；公网 VPS 上把专用服务账号 JSON 只读挂载，Google Cloud 环境优先使用工作负载身份。服务账号只授予发送消息所需的最小权限。

建议错误策略：

| FCM 结果 | 分类 | 处理 |
| --- | --- | --- |
| 2xx + message name | 已被 FCM 接受 | 保存 name 的受限标识；等待 App ACK |
| 400 `INVALID_ARGUMENT` | 请求或 Token 错误 | 解析结构化 details；仅在载荷已知有效且明确指向注册 Token 时停用 Token，否则作为代码/配置错误告警 |
| 401 | OAuth 凭据问题 | 强制刷新一次并只重试一次；仍失败则配置告警 |
| 403 | 权限或项目配置错误 | 不进入普通消息重试；配置告警 |
| 404 `UNREGISTERED` | FCM Token 已失效 | 清除 Token，设备置为等待重新登记；保留未过期密文供 App 同步 |
| 429 `QUOTA_EXCEEDED` | 限流 | 遵循 `Retry-After`；缺失时至少等待 60 秒，并加抖动 |
| 500 / 503 | 临时服务错误 | 至少 10 秒起步的指数退避加抖动，且不越过消息有效期 |
| 网络超时/连接中断 | 结果不确定 | 复用同一消息与密文重试；依靠 App message ID 去重 |

其他要求：

- FCM 调用设置连接、读取和总超时，不在请求处理线程无限等待。
- 重试调度使用持久化 `next_attempt_at`、有限租约和单进程锁；进程重启后继续。
- 对同一设备设置并发和速率上限，避免重试放大。
- FCM 401/403、持续 5xx、无效设备 Token、队列最老年龄超过阈值时产生不含敏感数据的本地运维告警。
- FCM 响应 message name 可保存截断标识或加密值；不得记录完整请求、响应、注册 Token 或 data payload。

## 11. 网关数据与清理

网关使用独立 SQLite、WAL 和单应用进程。建议数据模型只包含：

- 设备 ID、key ID、状态和激活/吊销时间；
- device token 的带密钥指纹；
- 加密后的 FCM Token 和设备认证密钥；
- 消息 ID、业务幂等键的带密钥指纹、优先级和有效期；
- 用网关 master key 再加密的端到端信封；
- FCM/ACK 状态、有限重试次数、下一次尝试时间和枚举错误码；
- 请求 nonce 的短期防重放记录。

不得保存：

- 邮箱凭据、邮件原始正文或附件；
- content root key 或 message key；
- 明文验证码、标题或摘要；
- 完整 Authorization、FCM Token、请求/响应载荷；
- NAS 管理会话、Cookie 或 CSRF Token。

清理建议：

- ACK、过期或吊销后立即清除消息信封；
- 消息状态与幂等指纹保留 7 天后删除；
- nonce 防重放记录在接受窗口结束后删除；
- 无内容审计最多保留 30 天；反向代理访问日志使用更短保留期；
- 日志轮转、数据库备份和错误追踪使用相同的敏感字段过滤规则；
- 网关密钥与数据库备份分开保存。恢复演练必须验证过期密文不会因旧备份重新进入投递队列。

## 12. 公网与 Android 部署安全

### 12.1 公网网关

```text
Internet :443
    │
    ▼
Caddy / Nginx：TLS、请求大小限制、限速
    │ 内部容器网络
    ▼
Push Gateway：单进程
    │
    ├── 受限 SQLite 卷
    └── 只读 Firebase 服务账号 Secret
```

- 公网只开放 TCP 443；应用端口不映射到公网，不在同一域名代理 Mail Sentinel 管理页。
- 使用独立域名和现代 TLS。证书自动续期失败必须告警；生产客户端不得提供“忽略证书错误”。
- 容器使用非 root 用户、只读根文件系统、最小 Linux capabilities、健康检查和自动重启。
- master key、publisher token、device admin token 通过服务器 Secret 或权限受限的环境文件注入，不写入镜像、Compose 示例或仓库。
- Firebase 服务账号使用独立项目和最小 IAM 权限。服务账号 JSON 是 Secret；Android 的 `google-services.json` 不得与它混淆。
- 备份 SQLite 前做一致性快照；备份加密、限制访问并验证恢复。不要把 Secret 与数据库放进同一未加密备份包。

### 12.2 Android App

- `android:usesCleartextTraffic="false"`，Network Security Config 只信任生产所需系统 CA；调试信任根只放在 debug 构建。
- 不默认做证书 pinning，避免证书轮换导致推送彻底失联；若未来启用，必须同时配置备份 pin 和可演练的轮换流程。
- FCM service、receiver 和内部 Activity 默认 `exported=false`；确需导出的入口使用显式权限与输入校验。
- 敏感数据只放 App 私有存储，禁用相关 Auto Backup/设备迁移；日志、崩溃报告和 analytics 默认关闭或严格脱敏。
- release APK 使用用户离线保管的正式签名密钥。debug APK、测试 Firebase 项目和测试网关不得复用生产凭据。
- 不申请通讯录、短信、存储、悬浮窗、辅助功能等与推送无关的权限。

## 13. 代码与配置规划

建议目录：

```text
push_gateway/                 # 独立 FastAPI 网关、模型、迁移和测试
deploy/push-gateway/          # 公网 Compose、反向代理和 Secret 示例
android/                      # Kotlin Android App
app/services/notifier.py      # 通道选择、冻结信封和受限回退
app/services/fcm_channel.py   # NAS 侧网关客户端与纯文本载荷转换
app/templates/                # 通道配置、配对、吊销和测试入口
tests/                        # NAS 通道与安全回归测试
```

配置原则：

- NAS 新增环境配置继续使用 `EMAIL_AGENT_` 前缀；管理员在 UI 保存的 publisher、device admin 和 content root key 使用现有 `Cipher` 加密。
- 网关使用独立 `PUSH_GATEWAY_` 前缀，敏感项不得提供可用于生产的默认值。
- 网关 URL、Firebase project ID、Android application ID、协议版本和 key ID 必须显式配置，不从不可信请求动态推断。
- 通道切换、重新配对、吊销、测试通知和数据库升级都要同步更新 `README.md` 与部署说明。

## 14. 实施阶段

### 阶段零：协议与迁移基线

- 冻结内部明文、AAD、base64url、HKDF 和请求签名规范。
- 创建 Python/Kotlin 共享黄金测试向量，覆盖 Unicode、空字段、过期时间和篡改失败。
- 设计现有 `notifications` schema 的可回滚升级路径；先验证旧数据保留和备份恢复。

### 阶段一：公网网关

- 完成三类 API 凭据、设备预配、HMAC 防重放、幂等消息接收、状态查询、FCM 投递、ACK、OAuth 令牌管理、清理和指标。
- 使用模拟 FCM 服务覆盖所有错误分类、超时不确定性和进程重启，不连接真实 Firebase。
- 完成 Docker Compose、Caddy/Nginx 示例、Secret 和备份恢复说明。

### 阶段二：Mail Sentinel 接入

- 增加通道选择、纯文本通知结构、冻结信封、加密设置、配对/吊销和测试通知。
- 实现受限回退、提交不确定性查询、免打扰一致性和敏感密文清理。
- 补充 schema 升级、CSRF、重新认证、幂等、租约、回退和日志脱敏测试。

### 阶段三：Android App

- 完成二维码导入、Keystore 包装、备份排除、HMAC、FCM Token 登记、本地去重、解密、隐私通知、ACK 和补偿同步。
- 适配通知权限、渠道关闭、前台、后台、锁屏、Doze、断网重连、Token 轮换、重装和 Keystore 失效。
- 生成可侧载签名 APK；正式签名密钥由用户离线保管。

### 阶段四：真实联调

- 仅在用户明确提供自己的 Firebase 项目、公网域名和测试设备后进行。
- 依次验证配对、测试消息、普通重要邮件、验证码、过期、撤销、FCM Token 失效、断线补偿和受限回退。
- 联调结束后清理测试设备、Token、服务账号文件、网关数据库和 App 本地密文；任何真实凭据、数据库或签名密钥不得提交仓库。

## 15. 测试矩阵

### 15.1 协议与密码学

- Python 与 Kotlin 对共享向量产生完全相同的 HKDF、AAD、AES-GCM 和 HMAC 结果。
- 修改 message ID、device ID、key ID、优先级、有效期、nonce 或 ciphertext 任一字节都会失败。
- 同一 key ID 不复用 nonce；同一通知重试复用同一冻结信封。
- 超限载荷在 NAS 拒绝或截断，最终 FCM data 始终低于硬上限。
- device token 泄露但没有 device_auth_key 时，无法登记 FCM Token、读取 pending 或 ACK。
- 首次登记前网关已经有认证密钥，攻击者不能利用 TOFU 抢注。
- 旧时间戳、重复 nonce、降低的 registration version 和跨设备签名全部拒绝。

### 15.2 NAS 通道

- 通知入队时冻结通道；更改全局设置不改变已入队通知路线。
- 网关重复接受相同 dedupe key 返回同一结果；相同键不同信封触发冲突。
- 只有 `otp`、`security`、critical `deadline` 能回退，且最多一次。
- 网关状态查询确认已接收后不回退；整体不可达的模糊故障允许一次可解释的极端重复。
- 夜间免打扰、过期清理、进程重启、租约恢复和当前 WxPusher 行为不回归。
- 成功、过期、吊销和回退终结后清除 NAS 通知内容加密载荷与 wire 信封。

### 15.3 网关

- 作用域隔离、速率限制、请求大小、幂等冲突和所有错误响应不泄露敏感字段。
- FCM 400/401/403/404/429/500/503、`Retry-After`、超时和无效 Token 使用正确状态转换。
- FCM 已接受但响应丢失时可能重发，App message ID 仍只显示一次。
- ACK、过期、吊销和备份恢复后不会重新投递已清理消息。
- publisher token 不能管理设备，device admin token 不能发布，device token 不能跨设备访问。

### 15.4 Android

- 前台、后台、锁屏、Doze、断网、强行停止后重开和系统重启场景。
- Android 13+ 首次拒绝/稍后允许通知权限；单个通知渠道关闭；电池优化限制。
- FCM Token 首次登记、轮换、旧版本重放、App 清除数据和重新配对。
- `onDeletedMessages` 与分页 pending 同步；ACK 丢失；相同消息重复到达。
- 锁屏/屏幕共享隐藏敏感正文，便利预览必须显式开启。
- 本地数据库、日志、崩溃报告和系统备份中没有通知明文、content root key 或 device token 原文。

自动化测试不得连接真实邮箱、WxPusher 或 Firebase。真实联调独立执行，且不得把真实 Secret、Token、数据库和 APK 签名密钥提交到仓库。

## 16. 验收标准

1. Android 无自建 WSS 长连接、无永久前台服务。
2. 手机前台、后台、锁屏和 Doze 场景按优先级接收并处理测试消息。
3. 网关数据库、日志和 FCM data 中不存在通知明文或完整验证码。
4. 仅持有 device token 无法抢注 FCM Token、读取 pending 或伪造 ACK。
5. 同一业务幂等键与同一 message ID 的正常重试只显示一次；已知极端重复场景有文档和测试。
6. 网络恢复后未过期消息能够补偿；过期验证码在网关和 App 都不会显示。
7. App 安全落地并创建通知后 ACK，网关立即删除密文；ACK 丢失不会重复显示。
8. 吊销后网关不残留该设备 FCM Token、认证密钥或未确认密文，旧凭据全部拒绝。
9. NAS 不开放公网端口，推送域名无法访问 Mail Sentinel 管理页面。
10. Android 没有发送、删除、移动、标记已读或远程配置接口。
11. 夜间免打扰在 WxPusher 与自建通道一致；网关和 App 不自行改变 NAS 判定。
12. 只有规定的紧急类别一次性回退；网关确认已接收后不回退。
13. Python/Kotlin 密码学黄金向量、Mail Sentinel 全量测试、网关测试、Android 单元/仪器测试和 release APK 构建全部通过。
14. 旧 SQLite 数据可以通过文档化升级路径保留；升级前备份和恢复演练通过。
15. `README.md`、配置示例、部署、吊销、备份和故障排查说明与实际行为一致。

## 17. 已知限制与后续方向

- FCM 依赖 Google Play 服务，以及手机和公网服务器对 Google 服务的可达性；部分地区或厂商系统无法可靠使用。
- 高优先级 FCM 是尽力快速投递，不是实时 SLA。用户强行停止 App、关闭通知权限或限制后台组件时无法保证到达。
- 端到端加密不隐藏设备标识、消息大小、时间、优先级和网络流量模式，也不能阻止被攻陷的网关丢弃消息。
- Android 设备是最终明文边界。启用通知内容预览会增加通知历史、截图、肩窥和辅助功能泄露风险。
- 首版单设备；未来多设备必须每设备独立 root key、device token、key ID、信封和 ACK，不能共享 content root key。
- 如果未来要求完全自托管，只能增加 WSS/长轮询等接收模式，并接受更高耗电、后台限制和常驻通知成本。
- 如需更强的恶意网关抵抗，可把设备 HMAC 升级为独立签名密钥对；这不改变消息内容加密层。

## 18. 官方参考资料

- [Firebase：Android 接收消息](https://firebase.google.com/docs/cloud-messaging/android/receive-messages)
- [Firebase：Android 消息优先级与后台处理](https://firebase.google.com/docs/cloud-messaging/android-message-priority)
- [Firebase：消息类型与 4096 字节载荷限制](https://firebase.google.com/docs/cloud-messaging/customize-messages/set-message-type)
- [Firebase：消息 TTL](https://firebase.google.com/docs/cloud-messaging/customize-messages/setting-message-lifespan)
- [Firebase：折叠消息、非折叠消息与积压限制](https://firebase.google.com/docs/cloud-messaging/customize-messages/collapsible-message-types)
- [Firebase：HTTP v1 错误码](https://firebase.google.com/docs/cloud-messaging/error-codes)
- [Firebase：大规模发送、超时与退避建议](https://firebase.google.com/docs/cloud-messaging/scale-fcm)
- [Firebase：FCM HTTP v1 授权与发送](https://firebase.google.com/docs/cloud-messaging/send/v1-api)
- [Firebase：注册 Token 管理](https://firebase.google.com/docs/cloud-messaging/manage-tokens)
- [Android：通知运行时权限](https://developer.android.com/develop/ui/compose/notifications/notification-permission)
- [Android：通知可见性](https://developer.android.com/reference/android/app/Notification)
- [Android：Android Keystore](https://developer.android.com/privacy-and-security/keystore)
- [Android：Auto Backup 与排除规则](https://developer.android.com/identity/data/autobackup)
- [Android：Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
