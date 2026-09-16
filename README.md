# CodeSignAuto

[中文（默认）](README.md) | [English](README.en.md)

CodeSignAuto 提供 Authenticode 代码签名、可选 PDF/PAdES 签名、本机 WPF
手工签名，以及 Windows Server 无人值守签名与 HTTP API。

## 安装需求

### 支持的系统

目标系统必须为 x64，并保持系统时间可靠同步。

- Windows 10 22H2；
- 受支持的 Windows 10 Enterprise / IoT Enterprise LTSC；
- Windows 11；
- Windows Server 2019、2022 或 2025 Standard/Datacenter Desktop Experience。

### 必需组件与下载地址

| 组件 | 下载地址 | 安装选择 |
| --- | --- | --- |
| ASP.NET Core Runtime 10 | [.NET 10 官方下载页](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) | 最新稳定版 `ASP.NET Core Runtime` 的 Windows x64 安装程序 |
| WPF / .NET Desktop Runtime 10 | [.NET Desktop Runtime 10 官方下载页](https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime) | “Run desktop apps”下的 x64 安装程序 |
| Certum SimplySign Desktop | [Certum 官方下载页](https://support.certum.eu/en/cert-offer-software-and-libraries/) | Windows 64-bit `SimplySign Desktop`；不需要安装 proCertum SmartSign |
| Windows SDK Signing Tools | [Windows SDK 官方下载页](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads) | 仅 Authenticode 需要：使用最新稳定版 Installer，并只选择 `Windows SDK Signing Tools for Desktop Apps` |

安装前请确认：

- .NET Windows Desktop Runtime 与 ASP.NET Core Runtime 为 10 或更高主版本；
- `C:\Windows\System32\SimplySignPKCS.dll` 已存在；
- SimplySign PKCS#11 module 能枚举目标证书及其私钥；
- 如需 Authenticode，已安装 Windows SDK Signing Tools，并存在 Windows SDK x64 `signtool.exe`。

补充说明：

- Setup 不下载或安装 .NET；缺少运行时或 SimplySign Desktop 时会在修改系统前提示。
- 目标机不需要 .NET SDK、Python、IIS 或 Hosting Bundle。
- 不需要安装完整 Windows SDK 开发组件或 Visual Studio；Authenticode 只需要 Windows SDK Signing Tools。
- Desktop Runtime 已包含基础 .NET Runtime，无需重复安装。
- 只使用 PDF 签名时不需要 SignTool。

### 主程序与 PDF 扩展

- 主程序是 `win-x64` framework-dependent 单文件，默认提供完整 Authenticode 能力。
- PDF helper 只存在于独立 PDF 扩展安装包，不会由主程序联网下载。
- 未安装 PDF 扩展时，管理界面隐藏 PDF 入口。
- 产品只监听 HTTP，不管理 TLS 证书。HTTPS 必须由外部反向代理提供。

## 选择安装模式

首次安装必须选择一种固定模式。安装器默认选中手工签名模式。

| 项目 | 手工签名模式 | 自动签名服务模式 |
| --- | --- | --- |
| 适用场景 | Windows 10/11 或管理员按需签名 | Windows Server 无人值守签名 |
| 签名进程 | 当前管理员打开程序后运行 | 后台 Service 与专用签名用户运行 |
| Windows Service | 不创建 | 创建 LocalSystem Service |
| 专用用户 / AutoLogon | 不创建 | 创建 `CodeSignAutoAgent` 与受保护 AutoLogon |
| HTTP API | 不开放 | 开放 |
| 关闭控制台 | 当前任务完成后可退出 | 不影响后台任务 |

模式规则：

- 升级继承已安装模式。
- 切换模式必须先卸载，再重新安装。
- 重复运行 Setup 不能迁移或修复安装模式。

安装程序和应用均支持中文与 English。安装器初次使用 Windows 显示语言；应用在
没有已保存偏好时默认中文，可在“应用设置”中切换。

## 快速开始

1. 下载 `CodeSignAutoSetup-<version>-win-x64.exe`。
2. 验证安装包的 Authenticode 签名和时间戳。
3. 双击安装包，选择语言和安装模式。
4. 手工模式安装后直接打开 CodeSignAuto。
5. 服务模式按提示重启，再由 Administrator 从公共桌面打开管理控制台。
6. 在“激活凭证”页导入完整 `otpauth://` 激活内容。
7. 在“概览”页确认目标证书和所需签名能力已就绪。
8. 如需 PDF，再安装当前 Release 提供的 PDF 扩展；未提供时继续使用最近的兼容版本。

仅服务模式还需处理 API token：

1. 从 `%ProgramData%\CodeSignAuto\install-token.txt` 读取一次性 token。
2. 立即保存到调用方 secret store。
3. 验证 API 后删除该文件。
4. 服务端只保留 token 的 SHA-256。

完整接口见 [HTTP API 文档](docs/API.md)。

## 验证发布包

公开 Release 始终包含：

- `CodeSignAutoSetup-<version>-win-x64.exe`。

仅当 PDF 有效输入相对上一主程序版本变化时，还包含：

- `CodeSignAutoPdfSetup-<version>-win-x64.exe`。

因此 PDF 安装包版本允许断档，例如从 `0.1.0` 直接到 `0.1.3`。

在 PowerShell 中验证当前目录的安装包：

```powershell
$setups = Get-ChildItem -LiteralPath . -File |
  Where-Object Name -Match '^CodeSignAuto(Pdf)?Setup-[0-9].*-win-x64\.exe$'

foreach ($setup in $setups) {
  $signature = Get-AuthenticodeSignature -LiteralPath $setup.FullName
  if ($signature.Status -ne 'Valid') {
    throw "release_signature_invalid: $setup"
  }
  if ($null -eq $signature.TimeStamperCertificate) {
    throw "release_timestamp_missing: $setup"
  }
}
```

安装包边界：

- 主安装包包含主程序、SQLite native 依赖、配置示例、运行策略、离线说明、
  SPDX SBOM、重复构建报告、MIT 许可证和第三方声明。
- PDF 安装包包含严格的 `extension.json`、已签 helper、MIT 许可证和第三方声明。
- Setup 会验证自身发布者、内嵌介质 hash 和成员闭包。
- 不需要也不应手工解压内嵌介质。

## 安装与升级

### 首次安装

核对签名后运行主安装包：

```powershell
& '.\CodeSignAutoSetup-0.1.0-win-x64.exe'
```

Setup 不接受参数，通过应用清单触发 UAC。安装前检查：

- Windows 版本与架构；
- .NET 运行时；
- 管理员权限和非域控制器；
- SimplySign Desktop 与 PKCS#11；
- 已有安装、目录、用户与 AutoLogon 冲突。

PDF helper 不是主程序安装前提。

#### 手工签名模式

安装内容：

- 受保护的程序介质；
- 当前管理员的本地任务数据目录；
- 公共桌面快捷方式；
- 安装收据和卸载注册项。

不会创建 Service、专用用户、AutoLogon、计划任务或 API token。
`%ProgramData%\CodeSignAuto` 只保存管理员可读的 `install.json` 安装收据。

#### 自动签名服务模式

安装内容：

- LocalSystem Service；
- 低权限签名用户 `CodeSignAutoAgent`；
- Windows profile；
- 仅存于 LSA private data 的随机密码；
- 受保护 AutoLogon；
- AtLogOn/InteractiveToken Agent 任务；
- ProgramData、配置和一次性 API token。

安装后必须按提示重启。管理员不需要进入或操作签名用户桌面。

服务默认监听 `http://0.0.0.0:7080`。安装器不会自动开放防火墙；请只在受控
内网、VPN 或可信反向代理中使用。

#### 已有 AutoLogon 冲突

服务模式检测到外部 AutoLogon 或残留凭据时，提供三个选择：

- 安全禁用并继续；
- 改用手工签名模式；
- 取消。

“安全禁用并继续”只执行以下操作：

- 将 `AutoAdminLogon` 设为 `0`；
- 删除 Windows 保存的 AutoLogon 凭据；
- 回读验证结果；
- 重新执行完整安装前检查。

该操作不会删除用户、修改账户密码，也不会显示、记录或使用密码内容。若所有权、
卸载状态、注册表类型或其他状态无法确认，安装器会拒绝清理。

### PDF 扩展

需要 PDF/PAdES 时，单独运行：

```powershell
& '.\CodeSignAutoPdfSetup-<version>-win-x64.exe'
```

规则如下：

- 当前 Release 没有 PDF Setup 时，继续使用最近的兼容扩展。
- PDF 版本无需与主程序连续或相同。
- 主程序按 `schemaVersion` 判断兼容性；`productVersion` 只标记扩展构建来源。
- 安装包离线验证 helper 的长度、SHA-256、代码签名和发布者。
- 管理控制台在下一次状态刷新后显示 PDF 入口。
- 找不到覆盖全部字符的受保护 Windows 系统字体时，返回
  `pdf_appearance_font_missing`。

### 原地升级

原地升级仅适用于使用 `CodeSignAuto` 安装标识的版本。改名前的安装不支持直接升级；
请先按旧版卸载流程完成卸载及重启，再安装本产品，旧设置与激活信息不会自动迁移。

同一主程序 Setup 同时负责全新安装和受控升级。

共同规则：

- 锁定并继承已安装模式；
- 精确验证安装收据、owner、ACL、产品注册和 PDF 扩展；
- 未知文件、路径漂移或身份不一致时，在替换前 fail closed；
- 不支持切换模式、修复安装或降级。

手工模式升级会保留：

- 当前管理员设置与 DPAPI 激活；
- 任务历史、spool 和已签名结果；
- 兼容的 PDF 扩展。

服务模式升级会在受控 drain 后保留：

- API token 与服务配置；
- 任务数据库与 spool；
- 专用用户、AutoLogon 和 DPAPI 激活；
- 兼容的 PDF 扩展。

遇到以下错误时，不要手工覆盖 Program Files：

- `restart_required`；
- `upgrade_drain_timeout`；
- `upgrade_state_uncertain`。

## 激活、登录与本机签名

### 导入激活信息

Administrator 在 WPF 控制台“激活凭证”页导入完整 `otpauth://` 内容。

- 手工模式：当前管理员进程解析，并用该用户的 CurrentUser DPAPI 保存。
- 服务模式：经本机双向身份校验的管理管道转发，由专用签名用户 Agent 保存。
- Service 不把激活 URI 写入磁盘或日志。
- 成功后清理输入框和剪贴板，协议响应不回传 secret。

导入不等于登录。请到“概览”页点击“登录”。

### 登录与就绪状态

- 空闲时不做后台登录或重试。
- 手工模式在本机任务提交时按需登录。
- 服务模式在 HTTP 请求通过预检后、创建任务前按需登录。
- 登录会重新检查 PKCS#11 token、证书和私钥。
- 失败不会保留新任务或上传文件。
- 仅看到 SimplySign Desktop 进程不代表可签名。

需要更换激活时：

1. 确认没有活动任务。
2. 在“激活凭证”页点击“清除”并确认。
3. 等待当前会话关闭和证书列表清空。
4. 导入新的完整激活内容。

该操作不会删除 Certum 账户或签名证书。

底层 `configure-otp` 仅用于目标签名用户上下文的离线修复：

```powershell
Get-Clipboard | .\CodeSignAuto.exe configure-otp
Set-Clipboard -Value ''
```

不要把激活 URI 放入命令行参数、环境变量、日志、工单或截图。

### WPF、托盘与任务历史

- 同一管理员 SID 只允许一个 WPF 实例；再次运行会激活现有窗口。
- 关闭窗口只隐藏到托盘。
- 服务模式退出控制台不会停止 Service、Agent 或后台任务。
- 手工模式有活动任务时拒绝退出；任务完成后可退出。
- 任务页保留历史记录和仍在保留期内的成功结果。

### 本机快速签名

支持选择：

- `.exe`、`.dll`、`.msi`、`.sys`、`.cat`；
- 已安装 PDF 扩展时的 `.pdf`。

签名过程：

1. 选择管理员可读的源文件、证书和参数。
2. 系统把输入复制到当前模式的受保护 spool。
3. 单 worker 完成签名和验证。
4. 成功结果先保存到受保护任务目录。
5. 控制台校验 size/hash 后，再另存到指定位置。

原文件保持只读；覆盖目标文件需要明确确认。服务模式的本机任务和 HTTP 任务共用
同一持久化 SQLite 队列。

## HTTP API 与外部 HTTPS

HTTP API 仅存在于自动签名服务模式。完整 schema、错误码、幂等和重试规则见
[HTTP API 文档](docs/API.md)。

部署边界：

- 默认地址：`http://<server>:7080`；
- 只直接用于受控内网、VPN 或可信反向代理；
- 产品不终止 TLS，也不管理服务端证书；
- 外部 HTTPS 客户端必须正常验证证书和 hostname，不要使用 `curl -k`；
- 除 `GET /health/live` 外，所有 `/v1` 接口都需要 Bearer token。

健康检查示例：

```bash
curl --fail-with-body "$BASE_URL/health/live"
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/v1/health/ready"
```

- `live` 只证明 Service 与 SQLite 可用。
- `ready` 才检查 Agent 会话、heartbeat、SimplySign、token、证书和私钥。
- 进程存在或 `live` 为 200 都不等于签名已就绪。

异步提交示例：

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: build-20260809-app-x64' \
  -F 'file=@./app.exe;type=application/octet-stream' \
  -F 'parameters={"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","appendSignature":false}' \
  "$BASE_URL/v1/jobs"
```

请求只接受 multipart 上传，不接受服务器本地路径或远程 URL。单文件上限为 512 MiB。

## 保留、设置与卸载

### 结果保留

| 模式 | 默认保留 | 可配置范围 |
| --- | --- | --- |
| 手工签名 | 168 小时 | 0–168 小时 |
| 自动签名服务 | 24 小时 | 0–168 小时 |

`0` 表示永久保留。活动任务不会因到期被删除。成功任务会及时清理输入和工作文件。

任务页的“清理已结束任务”会在确认后分批删除成功、失败和已过期任务的历史记录及结果文件，
包括设置为永久保留的任务。排队中、等待 Agent、正在签名或验证的任务，以及清理开始后才
结束的任务均保留。已导出到其他目录的签名副本不受影响；清理无法撤销，中途失败可重试。

启动时先恢复活动任务，并最多检查 100 个 spool 目录；历史记录和结果完整性检查在后台
每批最多处理 100 条，批次之间让出执行时间。文件下载仍会独立校验完整性。

### API token 轮换

API token 只存在于服务模式，可在“服务设置”中轮换。

- 安装时默认生成随机 token。
- 轮换时可填写指定 token；留空则生成新的随机值。
- 指定值需为 16–256 个字符，允许英文字母、数字及 `- _ . ~ + / =`，不接受空格或换行。
- 新 token 只显示一次，服务端仍只保存 SHA-256。
- 必须复制并确认后才能关闭对话框。
- 新配置生效后，旧 token 立即失效。

### 卸载

优先从 Windows“设置 → 应用 → 已安装的应用”卸载，也可运行：

从 Windows 设置启动卸载时会显示中英文卸载进度、结果和重启提示，不会弹出命令行窗口。
从 PowerShell 启动时使用等待式调用，可在当前终端输出稳定结果和错误代码，便于管理员排障：

```powershell
$process = Start-Process -FilePath 'C:\Program Files\CodeSignAuto\CodeSignAuto.exe' `
  -ArgumentList 'uninstall' -NoNewWindow -Wait -PassThru
$process.ExitCode
```

主程序卸载进入提升后的执行阶段后，会将有界、结构化的诊断写入
`%LocalAppData%\CodeSignAuto\logs\uninstall.log`。日志只记录产品版本、Windows
build、安装状态分类和稳定错误代码，不记录 token、SID、路径或配置内容。安装收据与
服务配置缺失、损坏或冲突时，卸载会在修改系统前停止；重启不能修复这类持久状态错误，
请保留安装目录和该日志用于排障。

PDF 扩展有独立卸载入口。卸载扩展不会影响主程序；卸载主程序时会先验证并移除
已安装的 PDF 扩展。

手工模式卸载：

- 删除程序、快捷方式、安装收据和卸载注册项；
- 删除当前管理员由本产品保存的 DPAPI 激活凭证；
- 默认保留任务历史和已签名结果；
- 成功后重启 Windows，完成程序文件的物理清理。

只有显式运行以下命令才删除受控数据：

```powershell
$process = Start-Process -FilePath 'C:\Program Files\CodeSignAuto\CodeSignAuto.exe' `
  -ArgumentList 'uninstall', '--purge-data', '--confirm', 'PURGE' `
  -NoNewWindow -Wait -PassThru
$process.ExitCode
```

服务模式卸载：

- mutation 前精确验证 install instance、owner、SID、账户、profile、AutoLogon、
  任务、Service、防火墙和 ACL；
- 仅删除本产品精确拥有的 Service、任务、用户、profile、AutoLogon 和受控数据；
- 成功后按提示重启，等待 purge 任务和 quarantine 消失；
- 重启完成前不要移动或删除 Program Files 中的包目录。

卸载绝不修改 Certum SimplySign Desktop、`SimplySignPKCS.dll`、Certum 证书或
部署者的反向代理。

## 故障排查

| 现象或错误码 | 处理建议 |
| --- | --- |
| `live` 503 | 检查 `CodeSignAuto.Service`、Event Log、`jobs.db` 所在卷和 ProgramData ACL。不要删除数据库。 |
| `ready` 503、`live` 200 | 检查非 0 签名用户会话、Agent 任务、系统时间、SimplySign Desktop、token、证书和私钥。 |
| `installation_mode_change_requires_reinstall` | 卸载后重装，并选择另一模式。 |
| `autologon_conflict` / `autologon_plaintext_password_present` | 在服务模式安装器中选择“安全禁用并继续”，或改用手工模式。 |
| `signtool_missing` | 安装或配置 Windows SDK x64 SignTool；PDF-only 不受影响。 |
| `pdf_support_not_installed` | 安装最近的兼容 PDF 扩展；Authenticode 仍可用。 |
| `pdf_helper_missing` / `pdf_helper_tampered` | 停止 PDF 签名，保留现场，从已验证 Release 重新安装。 |
| `otp_*` / `clock_not_synchronized` | 在控制台重新导入激活并校时；不要跨用户复制 DPAPI 文件。 |
| 长期 `waiting_for_agent` | 先恢复 readiness，不要用新 idempotency key 重复制造任务。 |
| `result_corrupt` | 保留 correlation ID，检查存储和 ACL，再从原输入创建新任务。 |

## Secret 泄漏应急

如果 API token、激活内容、反向代理私钥或签名凭据疑似泄漏：

1. 隔离调用方，保留不含 secret 的时间、主机、correlation ID 和审计证据。
2. API token：在“服务设置”中轮换，撤销旧客户端副本。
3. 激活内容：按 Certum 流程撤销或重置，再从控制台清除旧状态并重新导入。
4. TLS 私钥：在反向代理或证书系统中吊销并替换。
5. 可执行文件、helper、PKCS#11 或 ACL 可疑时，停止签名并从已验证发布物恢复。

不要把 secret 再贴入日志、工单、命令行或截图。

## 构建发布包

构建机要求：

- 干净、完整、非 shallow 的 Git 工作树；
- Windows x64；
- .NET 10 SDK；
- Python 3.12；
- `uv`。

基本流程：

```powershell
.\scripts\pre-release-check.ps1

$env:SIMPLYSIGN_SIGNING_BASE_URL = 'http://signing-ci.internal:7080'
$env:SIMPLYSIGN_SIGNING_BEARER_TOKEN = '<protected release secret>'
$env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL = '<certificate serial>'
.\scripts\build-release.ps1 -Version 0.1.0
```

发布脚本会执行：

- Python 测试、ruff 和冻结依赖验证；
- NuGet locked restore 与 .NET 测试；
- 两次一致的 framework-dependent publish；
- SPDX SBOM、catalog、闭包和签名验证；
- 主程序 Setup 的远程签名；
- PDF 有效输入变化时，构建并签名同版本 PDF Setup。

公开输出严格为一个主 Setup，加上本次需要发布时的一个 PDF Setup。脚本不会提交、
推送、打 tag 或创建 GitHub Release。

不含凭据的本地包装器：

```powershell
.\scripts\build-local-signed-release.ps1 `
  -Version <version> `
  -SigningBaseUrl 'http://signing-host.internal:7080' `
  -BearerTokenPath 'C:\BuildSecrets\simplysign-token.txt' `
  -SigningReferencePath 'C:\BuildSecrets\CodeSignAuto-reference.exe' `
  -DotnetRoot 'C:\Program Files\dotnet' `
  -UvPath '<path-to-uv.exe>'
```

Bearer token 只应通过受保护文件或进程环境进入发布子进程，不得写入仓库、命令行或日志。

## 许可证

CodeSignAuto 使用 [MIT License](LICENSE)。完整第三方版权与许可证文本见
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)。每个发布安装包都内嵌这两份文件。
