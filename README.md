# SimplySignAuto

SimplySignAuto 在 Windows Server 2025 Desktop Experience 上提供 HTTP 签名 API；支持 Authenticode 与 PDF/PAdES，并提供同一签名队列上的本机 WPF 快速签名。需要公网或跨不可信网络访问时，由部署者在产品外配置 HTTPS 反向代理。

一个 `SimplySignAuto.exe` 承载三个隔离角色：LocalSystem Windows Service 负责 HTTP、队列与受控文件；系统自动登录建立的低权限签名用户会话运行 headless Agent、TOTP、SimplySign Desktop 与签名工具；管理员在自己的桌面运行 WPF 控制台。管理员控制台只连接 Service 的本机管理管道，Service 再把明确的控制请求转发给 Agent；它不会把管理员加入签名管道，也不会在 Session 0 使用 CurrentUser DPAPI 或运行 SimplySign。

## 快速开始

1. 下载并核对 `SimplySignAutoSetup-<version>-win-x64.exe` 的 Authenticode 签名。
2. 双击安装包，按向导完成主程序安装。
3. 重启 Windows，让签名用户 AutoLogon 会话、Agent 任务和 Service 完整启动。
4. Administrator 登录后，从公共桌面的“SimplySignAuto”快捷方式打开管理控制台。
5. 在“激活凭证”页导入完整 `otpauth://` 激活内容，再到“概览”确认代码签名已就绪。
6. 从 `%ProgramData%\SimplySignAuto\install-token.txt` 取出一次性 API token，保存到调用方 secret store，验证后删除该文件。
7. 按需单独安装 `SimplySignAutoPdfSetup-<version>-win-x64.exe`；不使用 PDF 签名时无需安装。
8. HTTP 接口、请求 schema、响应和重试规则见 [HTTP API 文档](docs/API.md)。

## 系统前提

- Windows Server 2019、2022 或 2025 Standard/Datacenter Desktop Experience，
  或受支持的 Windows 10 Enterprise/IoT Enterprise LTSC、Windows 11，均为
  x64；系统时间必须可靠同步。
- 需要稳定版 .NET Windows Desktop Runtime 与 ASP.NET Core Runtime 10 或
  更高主版本；Setup 不下载或安装 runtime，缺失时不会开始产品安装。
- 已安装 Certum SimplySign Desktop，并存在 `C:\Windows\System32\SimplySignPKCS.dll`；Setup 在创建用户或修改系统前检查两者，缺失时直接提示安装。
- Authenticode 能力需要 Windows SDK x64 `signtool.exe`；只使用 PDF 时不需要 SignTool。
- 产品自身不终止 TLS，也不导入或更新服务端证书。若使用 HTTPS，部署者负责反向代理、证书更新、外部主机名和代理到本机 HTTP 端口的访问控制。
- 已确认 SimplySign PKCS#11 module 可由签名用户加载，并能枚举目标证书及其私钥；API 以证书序列号选择证书，不配置证书或 TSA 别名。
- 主程序是 `win-x64` framework-dependent 单文件；目标机不需要安装
  Python。默认只安装完整的 Authenticode 能力。PDF/PAdES helper 只包含在
  独立的 PDF 扩展安装包中，不联网下载；扩展未安装时，管理界面隐藏 PDF
  入口，Service 与 Agent 也不会自动获取可执行文件。

标准安装会创建固定的专用普通账户 `SimplySignAgent`，管理员不需要也不应手工登录该账户。管理员控制台需要 Administrator 自己的非 0 交互桌面会话；后台签名在控制台关闭、退出或管理员断开桌面后继续运行。

## 验证发布包

公开发布目录只包括两个签名的离线安装包：
`SimplySignAutoSetup-<version>-win-x64.exe` 和
`SimplySignAutoPdfSetup-<version>-win-x64.exe`。部署前核对两者的
Authenticode 签名、时间戳和预期发布者：

```powershell
$setups = @(
  '.\SimplySignAutoSetup-0.1.0-win-x64.exe',
  '.\SimplySignAutoPdfSetup-0.1.0-win-x64.exe'
)
foreach ($setup in $setups) {
  $signature = Get-AuthenticodeSignature -LiteralPath $setup
  if ($signature.Status -ne 'Valid') { throw "release_signature_invalid: $setup" }
}
```

主安装包内嵌一份已签 catalog 闭合的安装介质，包括主程序、SQLite native
依赖、配置示例、运行时策略、离线说明、SPDX SBOM、重复构建报告、MIT
许可证和完整第三方声明。PDF 扩展安装包内嵌严格的 `extension.json`、已签
helper、MIT 许可证和相同的第三方声明。两个
安装包都会先验证自身发布者、内嵌介质 hash 和成员闭包，再开始安装；用户
不需要也不应手工解压内嵌介质。

## 首次安装

1. 核对签名后，双击主程序 Setup：

```powershell
& '.\SimplySignAutoSetup-0.1.0-win-x64.exe'
```

Setup 不接受参数，并通过应用清单触发 UAC。它先检查 Windows、.NET
runtime、管理员、非域控制器、SimplySign Desktop 与 PKCS#11；PDF helper
不是基础安装前提。检查通过后才创建 `SimplySignAgent`、Windows profile、
仅存于 LSA private data 的随机密码、受保护 AutoLogon、
AtLogOn/InteractiveToken Agent 任务、ProgramData、配置和 LocalSystem
Service，并在公共桌面创建指向固定安装路径的“SimplySignAuto”快捷方式。SignTool 缺失只关闭 Authenticode 能力；PDF 扩展未安装时不影响
基础产品就绪，也不会显示 PDF 操作入口。已有同名用户、
其他 AutoLogon、路径/ACL/owner/readback 不一致会 fail closed；失败会回滚
本轮 exact-owned 变更，无法确认回滚时返回 `setup_state_uncertain`。

安装成功会生成一次 API token，并暂存到管理员可读的 `%ProgramData%\SimplySignAuto\install-token.txt`。立即复制到客户端 secret store，验证访问后删除该文件；服务端只保存 token 的 SHA-256。安装状态会提示需要重启。

2. 重启 Windows。LocalSystem Service 使用普通自动启动并在交互登录前由 SCM 启动；系统随后用受保护 AutoLogon 建立签名用户的非 0 会话，计划任务在该会话启动 headless Agent。管理员无需切换到或操作签名用户桌面。日常登录 Administrator 后使用桌面“SimplySignAuto”快捷方式；也可直接运行 `C:\Program Files\SimplySignAuto\SimplySignAuto.exe`。程序要求提升权限并只启动管理控制台，不读取管理员的 Agent 配置，也不启动第二个 Agent。

3. 默认监听 `http://0.0.0.0:7080`，只适用于受控内网、VPN 或可信反向代理；标准安装不自动打开防火墙。产品不提供内置 HTTPS 或证书管理。需要 HTTPS 时，由部署者在产品外配置反向代理并将流量转发到此 HTTP 端口；证书签发、续期、主机名校验和代理访问控制均由部署者负责。

4. 需要 PDF/PAdES 时，再核对并运行独立发布的
   `SimplySignAutoPdfSetup-<version>-win-x64.exe`。PDF 扩展不要求与主程序版本
   相同；主程序按扩展清单的 `schemaVersion` 判断格式兼容性，清单中的
   `productVersion` 仅标记扩展构建来源。安装包离线验证 helper 的长度、
   SHA-256、代码签名和发布者后原子安装扩展；管理控制台在下一次状态刷新后
   显示 PDF 入口。PDF 可见签章按实际文本从受保护的 Windows Fonts 目录选择
   覆盖全部所需字形的系统字体；没有合格字体时返回
   `pdf_appearance_font_missing`。无需 PDF 时不要安装该扩展。

同一主程序 Setup 同时负责全新安装和受控原地升级。检测到现有安装时，Setup
只接受签名、catalog、install instance、owner marker、SID、账户/profile、ACL、
Service、Agent task、AutoLogon、产品注册和可选 PDF 扩展全部精确匹配的本产品
安装；未知文件、路径漂移或身份不一致会在替换前 fail closed。修复安装和降级
仍不支持。

## 导入 SimplySign 激活信息

首次部署由 Administrator 在自己的 WPF 控制台“激活凭证”页导入完整 `otpauth://` URI。控制台经受双向身份校验的本机管理管道把 URI 单次转发给 Service，Service 不写磁盘或日志，再交给签名用户 Agent 解析并用该用户的 CurrentUser DPAPI 保存；管理员进程不会生成管理员自己的 `otp.dat`。成功后输入框和剪贴板会清理，协议响应不回传 secret。导入凭证本身不会登录或启动 SimplySign；管理员可以在概览页点击“登录”。空闲时软件不做后台登录或重试；HTTP API 收到参数与文件类型均可接受的签名请求后，才会在创建任务和写入 spool 前按需计算 TOTP、调用 `/autologin`，并重新检查 PKCS#11 token、证书和私钥。登录或校验失败时直接返回 `503`，不保留任务或上传文件。

需要重新测试激活导入时，先确认没有活动签名任务，再在“激活凭证”页点击“清除”并确认。软件会关闭当前 SimplySign 会话、删除当前签名用户由本产品保存的 DPAPI 激活内容，并清空当前证书列表；之后可重新导入新的 `otpauth://` URI。该操作不会删除 Certum 账户或签名证书。若导入时提示“签名代理尚未就绪”，首次安装应先重启 Windows；已经重启时等待 Service 与签名用户 Agent 启动后再试。

底层 `configure-otp` 只写调用者的 CurrentUser DPAPI，不能由 Administrator 代替签名用户运行；标准管理员部署不要使用下面的兼容入口。只有明确在签名用户上下文做离线修复时，才可从标准输入导入：

```powershell
Get-Clipboard | .\SimplySignAuto.exe configure-otp
Set-Clipboard -Value ''
```

不要把 URI 作为命令行参数、环境变量、日志字段、工单正文或截图内容。管理员导入后在“概览”页点击“登录”：Service 只转发请求，实际登录仍在签名用户 Agent 内串行执行；已有签名任务时导入、清除和登录会拒绝并发修改。必须看到目标 token、证书与私钥均 ready；仅看到 SimplySign Desktop 进程不代表可签名。

## WPF、托盘与本机快速签名

Administrator 在自己的非 0 桌面会话直接运行 `SimplySignAuto.exe` 打开管理控制台；未提升时程序触发 UAC。窗口首次使用默认横向 `1024×768`，同一管理员 SID 只允许一个控制台实例，再次运行会激活现有窗口。控制台不加载签名用户的 `agent.json`，也不启动或停止 Agent。

关闭窗口只会隐藏到管理员托盘；选择“退出程序”只退出控制台及其管理连接。两种操作都不会停止 Service、Agent、SimplySign Desktop 或当前签名任务，管理员以后重新打开控制台即可恢复查看。

“激活凭证”页显示每张已发现证书的三行信息：CN、完整规范化序列号、当地时间有效期；不可用或已过期证书仍保留并显示状态。序列号支持普通选取和 `Ctrl+C`，双击会复制完整序列号。

本机快速签名在“快速签名”页选择管理员可读的 `.exe`/`.dll`/`.msi`/`.sys`/`.cat` 或 `.pdf`，再选择证书和类型参数。控制台自己打开源文件，经 Service 分配的受控 spool lease 上传 size/hash；Agent 只读取 spool，不接收管理员桌面路径。签名结果由控制台重新验证 size/hash 后保存回管理员选择的位置，原文件保持只读，覆盖需要明确确认。complete 使用同一 request/job/lease 幂等重试，断线或超时不会把“结果未知”误报成确定失败。本机任务与 API 共用 SQLite、全局单 worker、恢复与保留策略。

## HTTP API 与外部 HTTPS

完整、可直接交给调用方的接口规范见 [docs/API.md](docs/API.md)。本节只保留常用示例和部署边界；请求字段、响应 schema、错误码、幂等与重试规则以接口文档为准。

以下示例假设：

```bash
BASE_URL=http://signer.internal:7080
TOKEN='从 secret store 注入，不要写入脚本仓库'
```

产品监听 HTTP，因而只应直接用于受控内网、VPN 或同机/可信网络中的反向代理。若 `BASE_URL` 指向部署者配置的 HTTPS 反向代理，客户端仍必须正常校验证书和 hostname；不要使用 `curl -k`。除匿名 liveness 外，所有 `/v1` 路由都要求精确的 `Authorization: Bearer <token>`。

### 异步提交、轮询和下载

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: build-20260809-app-x64' \
  -F 'file=@./app.exe;type=application/octet-stream' \
  -F 'parameters={"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","appendSignature":false}' \
  "$BASE_URL/v1/jobs"

curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/v1/jobs/00000000-0000-0000-0000-000000000000"

curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -o app.signed.exe \
  "$BASE_URL/v1/jobs/00000000-0000-0000-0000-000000000000/result"
```

成功创建返回 HTTP 202、`jobId`、`statusUrl`、`resultUrl` 与 `expiresAt`。`Idempotency-Key` 可省略；提供时必须是 1–128 个可打印 ASCII 字符。对相同 key 重试相同请求会返回同一任务，不同请求会返回 `idempotency_conflict`。单文件上限 512 MiB，multipart 只允许一个 `file` 和一个 `parameters`。

### 最多等待 120 秒的同步调用

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: invoice-20260809-42' \
  -F 'file=@./invoice.pdf;type=application/pdf' \
  -F 'parameters={"kind":"pdf","certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","page":1,"box":[36,36,220,110],"fieldName":"Signature1","reason":"Approved","location":"Shanghai"}' \
  -o invoice.signed.pdf \
  "$BASE_URL/v1/sign?waitSeconds=120"
```

若 1–120 秒内成功，返回 HTTP 200 文件；失败返回 problem JSON；超时仅返回 HTTP 202 与同一任务地址，不会取消持久化任务。脚本应先检查 HTTP 状态再把响应当作签名文件。

### 签名参数 schema

字段名、大小写和集合是严格的；未知、重复或错误类型字段都会返回 `invalid_parameters`。外部请求必须使用规范化 X.509 序列号选择证书，不能传可执行路径、DLL 路径、PKCS#11 token/key/object ID、TSA URL 或任意进程参数。请求不包含 TSA 字段；Authenticode 与 PDF 均固定使用 Certum RFC 3161 服务。

Authenticode（文件扩展名必须为 `.exe`、`.dll`、`.msi`、`.sys` 或 `.cat`）：

```json
{
  "kind": "authenticode",
  "certificateSerialNumber": "52A1B4C9",
  "digestAlgorithm": "sha256",
  "appendSignature": false
}
```

PDF：

```json
{
  "kind": "pdf",
  "certificateSerialNumber": "6F09D233",
  "digestAlgorithm": "sha256",
  "page": 1,
  "box": [36, 36, 220, 110],
  "fieldName": "Signature1",
  "reason": "Approved",
  "location": "Shanghai"
}
```

`certificateSerialNumber` 为规范化十六进制 X.509 序列号；同一规范化序列号找不到时返回 `certificate_not_found`，发现多张时仅该序列号返回 `certificate_serial_ambiguous`，不可用于所选签名类型时返回 `certificate_not_usable`。`digestAlgorithm` 固定为 `sha256`；`fieldName` 为 1–64 个字符并以 ASCII 字母开头，只允许字母、数字、`_`、`.`、`-`。`page` 为 1–10000；`box` 顺序为 `[left,bottom,right,top]`，必须是有限数且 `left < right`、`bottom < top`；`reason`/`location` 可省略，最多 128 字符且不得含控制字符。

`POST /v1/jobs` 与 `POST /v1/sign` 会在入队前核对当前 Agent 会话、对应签名
能力和证书摘要。连接断开、heartbeat 过期或对应能力未就绪时返回 HTTP 503；
能够提前确定的参数、文件类型和证书错误直接返回 problem JSON，不创建任务，
也不保留 spool 文件。PDF 扩展未安装不影响已就绪的 Authenticode 请求。

## 状态、错误和健康检查

任务状态依次可能为 `queued`、`waiting_for_agent`、`signing`、`verifying`，终态为 `succeeded`、`failed` 或 `expired`。仅 `succeeded` 可下载；未完成为 409，过期为 410，结果 size/hash 验证失败为 500 `result_corrupt` 并把任务防御性转为 failed。下载不支持 range。

常见稳定错误码：

- 请求：`invalid_parameters`、`unsupported_type`、`file_signature_mismatch`、`file_too_large`、`idempotency_conflict`、`job_not_found`、`job_not_complete`。
- Agent/会话：`agent_unavailable`、`agent_session_zero`、`agent_wrong_user`、`agent_already_running`、`agent_protocol_mismatch`。
- 证书目录：`certificate_catalog_unavailable`、`certificate_not_found`、`certificate_serial_ambiguous`、`certificate_not_usable`。
- OTP/SimplySign：`otp_missing`、`otp_wrong_user`、`otp_corrupt`、`otp_profile_invalid`、`clock_not_synchronized`、`simplysign_exe_missing`、`simplysign_close_timeout`、`simplysign_login_failed`、`token_missing`、`certificate_missing`、`private_key_missing`、`pkcs11_session_lost`。
- 签名：`signtool_missing`、`invalid_signable_file`、`already_signed`、`authenticode_sign_failed`、`authenticode_verify_failed`、`pdf_helper_missing`、`pdf_helper_tampered`、`pdf_invalid`、`pdf_sign_failed`、`pdf_verify_failed`、`tsa_failed`。
- 持久化：`spool_write_failed`、`input_corrupt`、`result_corrupt`、`recovery_exhausted`、`job_expired`、`service_unavailable`、`internal_error`。

响应中的 `correlationId` 用于本机诊断；API 不返回内部路径、SID、连接 ID、原始异常、请求 header/body、进程参数或 secret。

健康检查：

```bash
curl --fail-with-body "$BASE_URL/health/live"
curl --fail-with-body -H "Authorization: Bearer $TOKEN" "$BASE_URL/v1/health/ready"
```

- `/health/live` 匿名，只执行真实 SQLite 健康查询；数据库不可用返回 503。
- `/v1/health/ready` 需要 Bearer。只有数据库与队列可读、当前连接已收到首个 heartbeat、Session ID 大于 0、heartbeat 年龄在 0–15 秒、能力列表合法且至少配置一个能力、每个已配置能力的 SimplySign/token/certificate/private-key 状态均精确 ready 时才返回 200；否则返回 503。未来时间戳也不算 ready。
- readiness 返回安全的连接/会话摘要、`authenticode`/`pdf` 分能力状态和诚实队列计数，不返回 SID、connection ID、磁盘路径或 secret。liveness 为 200 不代表可以签名。

Agent 发布全局七态会话：`UNKNOWN`、`CHECKING`、`READY`、`LOGIN_REQUIRED`、`LOGINNING`、`WAIT_TOKEN`、`FAILED`。Service 启动准备或签名前若 SimplySign 已在线，只探测并刷新一次证书目录，不调用 `/autologin`；离线时一个逻辑触发最多调用两次 `/autologin`，并发任务共享同一轮。生成 TOTP 时要求当前 counter 至少还剩 3 秒；不足 3 秒会等待下一 counter，而不是浪费一次尝试。首次 token 等待窗口失败后可在下一 counter 再试一次；第二次失败进入 `FAILED` 并至少冷却 60 秒。

每个任务在签名前取得绑定当前证书目录快照的 ready lease；旧 heartbeat、旧目录或上一任务的 `READY` 不是签名依据。空闲时没有登录 keepalive：每 5 分钟的健康检查只做零等待进程探测，不登录、不等待 token、也不刷新证书目录。SimplySign 会话空闲约 1800 秒过期后，界面会如实显示需要登录；管理员仍可手工点击“登录”。HTTP API 收到签名请求时，如果当前 Agent 连接和 heartbeat 有效但签名会话未就绪，会在写入 spool 和创建任务前通过与界面相同的控制通道发起一次登录；并发请求共享同一次进行中的登录。登录失败直接返回 503，不创建任务，也不遗留上传文件。Agent/pipe 在探测或登录失败后保持运行，后续请求可再次尝试。

`agent --background` 只启动签名用户的 headless Agent 且不保留命令行窗口；脱敏诊断写入该用户 `%LOCALAPPDATA%\SimplySignAuto\logs\desktop-agent.log`，按 64 MiB 硬上限循环覆盖。无参数启动只运行管理员控制台。需要前台观察 Agent 时使用 `agent --console`，安装、配置和版本命令仍保持正常终端输入输出。

## 保留、轮换、升级与卸载

结果保留默认为 24 小时，可在管理员控制台“服务设置”页配置为 0–168 小时；`0` 显示为“永久保留”。清理每小时运行：活动任务永不因到期被删除；永久任务不参与到期清理；有限保留的终态任务只有在受控目录完整删除成功后才标记 expired，删除失败保持原 DB 状态并在后续周期重试。启动恢复会清理至少 1 小时的非活动 `.part`，验证成功结果并删除其 input/work；未知目录移到同级 quarantine，不覆盖现有隔离项。

API token 轮换也在同一“修改服务设置”对话框选择。控制台以事务式配置替换并重启/验证 Service，新 token 只在结果步骤显示一次，必须复制并明确确认后才能关闭；旧 token 在新配置生效后立即失效。先在客户端 secret store 建立新版本，完成服务端轮换后原子切换所有客户端，不要同时长期保存新旧 token。

升级前先关闭 Administrator 管理控制台，并核对新 Setup 的签名。签名用户已有
活动交互会话时，直接运行新主程序 Setup：Service 先停止接收新任务并有界等待
队列清空，再退出 SimplySign、停止 Agent task 与 Service；新介质在受保护 staging
中完成签名、catalog、hash、成员闭包和兼容性校验后，才在同一卷原子切换。
升级保留 API token、服务配置、任务数据库、spool、专用用户、AutoLogon、DPAPI
激活凭证和兼容的独立 PDF 扩展。新 Service/Agent 及 heartbeat 验证成功后才删除
旧版本备份；失败会恢复旧介质和旧运行时。

签名用户交互会话缺失、已安装程序文件仍被占用或当前旧版本不支持安全 drain
时，Setup 返回 `restart_required`，不会静默安排重启；活动任务超过等待上限返回
`upgrade_drain_timeout`。无法证明旧版本已经完整恢复时返回
`upgrade_state_uncertain`，此时不要手工覆盖 Program Files，应保留现场排查。
首次安装仍需要一次重启，修复安装和降级仍不支持。

标准卸载从 Windows“设置 → 应用 → 已安装的应用”选择 SimplySignAuto，
也可以直接运行已安装主程序：

```powershell
& 'C:\Program Files\SimplySignAuto\SimplySignAuto.exe' uninstall
```

PDF 扩展在“已安装的应用”中有独立卸载入口；卸载扩展只移除 PDF helper。
卸载主产品时也会先验证并移除已安装的 PDF 扩展，避免留下孤立组件。

主程序在需要时触发 UAC。生产环境会在任何 mutation 前一次性验证 install instance、owner marker、SID、账户名、Users-only 身份、profile receipt/ProfileList、AutoLogon/LSA secret 指纹、任务、Service、防火墙和受控目录 ACL。只有全部证据精确匹配时，才按固定顺序停止 Agent 任务与 Service、注销 exact SID 会话并确认 profile hive 卸载、禁用本产品 AutoLogon、删除本产品创建的用户及 exact-owned profile，最后隔离 ProgramData。禁用阶段保留受保护的 exact-owner 续跑凭据，因此中途失败可再次从“已安装的应用”或同一主程序启动卸载；下次启动的 SYSTEM cleanup 删除物理 quarantine，并在确认同一 owner/SID 后清除 LSA secret、恢复安装前的 Winlogon 值。

卸载成功后先重启一次，确认 `SimplySignAuto.Purge.*` 清理任务和 quarantine 已消失，再删除 `C:\Program Files\SimplySignAuto` 包目录。清理任务会校验并运行该目录中同一哈希的 EXE；在重启完成前移动、替换或删除包目录会使物理清理失败。

任一 owner/SID/profile/readback 被替换或状态不确定时，整批卸载在首个 mutation 前拒绝；卸载不会根据用户名猜测。通过高级 `ExistingUser` 模式接入的外部账户会保留账户和 profile，但仍清理本产品受控数据。卸载绝不删除、修改或注销 Certum SimplySign Desktop、`SimplySignPKCS.dll`、Certum 安装注册项或证书，也不会触碰部署者的反向代理；不要手工递归删除未知或含 reparse point 的目录。

## 故障排查

- live 503：检查 `SimplySignAuto.Service`、Event Log、`jobs.db` 所在卷和 ProgramData ACL；不要删除数据库来“修复”。
- ready 503 但 live 200：确认签名用户已登录非 0 会话、计划任务在该用户下运行、系统时间同步、SimplySign Desktop 与目标 token/certificate/private key 可枚举，再看分能力 reason/status。
- `signtool_missing`：确认 agent JSON 指向 Windows SDK x64 SignTool，文件未被替换且签名用户可读。
- `pdf_support_not_installed`：基础产品可继续使用 Authenticode；由管理员
  运行兼容清单版本的 PDF 扩展安装包，不要求与主程序版本相同。扩展安装包
  从内嵌 `extension.json` 读取
  版本、长度、SHA-256 与发布者校验信息，全程不联网。
- `pdf_helper_missing`：已发布 state 指向的 helper 无法启动；停止 PDF
  任务并检查 ProgramData tools root 与受保护 state。
- `pdf_helper_tampered`：停止 Agent，保留可疑 `.part`、版本目录、state 与
  descriptor 供取证，核对长度、SHA-256、SHA-512、签名发布者、ACL、hardlink
  和 reparse point；失败路径不会自动删除或覆盖未知替换物。
- `otp_*` / `clock_not_synchronized`：由管理员控制台重新导入 URI 并校时；不要复制 DPAPI 文件或手工进入签名用户桌面。
- 任务长期 `waiting_for_agent`：readiness 必须先恢复；不要重复使用新 idempotency key 制造更多任务。
- 下载 `result_corrupt`：保留 correlation ID，检查存储介质和 ACL，从原输入重新建立新任务；不要直接信任或复制现有 result。

## Secret 泄漏应急

一旦 API token、`otpauth://` URI/TOTP、反向代理 TLS 私钥或签名凭据疑似泄漏：

1. 隔离调用方并保存不含 secret 的时间、主机、correlation ID 和审计证据；不要把 secret 再贴进日志或工单。
2. API token：立即在管理员控制台“服务设置”页轮换并撤销旧客户端副本。
3. OTP URI/TOTP：按 Certum 流程撤销/重置激活，由管理员控制台清除旧状态并重新导入；清空剪贴板和未经保护的临时文件。
4. 反向代理 TLS 私钥：在代理或证书管理系统中吊销并替换证书，验证外部网址、代理转发规则和所有客户端信任链；SimplySignAuto 不管理该证书。
5. 若 helper、可执行文件、PKCS#11 模块或 ACL 可能被改动，停止签名、保全 hash/签名证据，从已验证发布物在干净快照恢复，完成两类签名验证后再开放 API。

## 构建发布包

在干净的 Windows x64 构建机安装 .NET 10 SDK、Python 3.12 与 `uv`，然后运行：

```powershell
.\scripts\pre-release-check.ps1

$env:SIMPLYSIGN_SIGNING_BASE_URL = 'http://signing-ci.internal:7080'
$env:SIMPLYSIGN_SIGNING_BEARER_TOKEN = '<protected release secret>'
$env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL = '<certificate serial>'
.\scripts\build-release.ps1 -Version 0.1.0
```

发布前检查要求完整（非 shallow）且干净的 Git 工作树，检查当前跟踪文件与全部
本地可达历史中的敏感/生成物路径、超大当前文件、忽略规则和发布必需文档。发现
历史污染时先停止发布并人工确认是否需要改写历史；脚本不会自动删除文件或改写 Git。

脚本只清理当前版本 build 目录，执行 `uv sync --frozen`、Python
测试/ruff、NuGet locked restore、.NET 测试、两次一致的 `win-x64`
framework-dependent publish、PyInstaller helper 构建与真实验证、helper
远程签名/时间戳/签后 hash、严格 `extension.json` 生成、SPDX SBOM、
远程签名 catalog、两个确定性内嵌 payload，以及主程序和 PDF 扩展两个
远程签名 Setup。签名 Base URL 可由发布环境配置为 HTTP 或 HTTPS；客户端
不跳过 TLS 或主机名校验，Bearer token 只从进程环境读取且不进入命令行。
公开输出严格只有这两个安装包。脚本不提交、推送、打 tag 或发布远端
Release。

构建机也可以使用不含凭据的通用包装脚本。签名 API 地址、受保护 token
文件和一个已由目标证书签名的参考文件都在运行时传入；脚本只把 token
写入子进程环境，并在发布结束后恢复环境：

```powershell
.\scripts\build-local-signed-release.ps1 `
  -Version <version> `
  -SigningBaseUrl 'http://signing-host.internal:7080' `
  -BearerTokenPath 'C:\BuildSecrets\simplysign-token.txt' `
  -SigningReferencePath 'C:\BuildSecrets\SimplySignAuto-reference.exe' `
  -DotnetRoot 'C:\Program Files\dotnet' `
  -UvPath '<path-to-uv.exe>'
```

脚本本身不保存 Bearer token、证书序列号或固定签名服务地址。

## 许可证

SimplySignAuto 采用 [MIT License](LICENSE)。主程序与 PDF 扩展使用的第三方
组件、版权声明和完整许可证文本见
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)；两个安装包都内嵌这两份
文件。
