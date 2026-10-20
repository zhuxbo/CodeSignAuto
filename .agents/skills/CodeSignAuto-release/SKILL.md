---
name: CodeSignAuto-release
description: 在 CodeSignAuto 仓库中进行新会话上手、Windows 构建测试、安装卸载、签名发布、部署验证或发布前审计时使用。提供项目架构、主程序与 PDF 扩展边界、凭据安全要求、分阶段验证与发布门禁。
---

# CodeSignAuto 发布与验证

## 快速定向

先读 `README.md`、`docs/API.md`、`git status --short` 和最近提交。只在需要时打开相关生产代码与测试；不要先读取 `.superpowers/` 中的历史过程记录。

主要边界：

- `CodeSignAuto.exe` 同时承载 LocalSystem Service、签名用户 Agent 和管理员 WPF 控制台，但三种身份与会话必须隔离。
- 主安装包默认只提供完整代码签名；PDF helper 由独立 PDF 扩展安装包安装，未安装时主界面隐藏 PDF 功能。
- 产品只监听 HTTP。需要 HTTPS 时由用户配置反向代理；不要恢复 TLS/PFX 产品设置或“证明已删除功能不存在”的镜像测试。
- 公共发布始终只有主程序 Setup，并在 PDF 有效输入相对上一主程序版本变化时
  额外包含同版本 PDF 扩展 Setup；PDF 版本允许断档。

## 环境与安全

- 开发环境配置使用仓库根目录的 `development.local.json`（已忽略，不提交），字段示例见 `development.sample.json`。本地配置允许保存签名 token 文本，但不得整体打印或纳入日志；sample 只保留占位值，不得写入实际主机地址或凭证。
- Windows 构建机可使用本地 SSH 配置执行构建和测试。
- Windows 发布验证机只安装、重启、登录、调用 API 和做真实签名验证，禁止构建源码。
- 优先 SSH 和仓库脚本；只有必须观察 WPF 交互时才使用桌面操作。
- Bearer token 只从受保护文件或环境进入发布子进程；不要在命令行、日志、截图或回复中输出。
- 不读取或输出 TOTP、Base32 secret、完整 `otpauth://`、私钥、RDP 密码或带凭据 URI。
- 用户说“提交”或已授权分 Task 提交时只做本地 commit；push、tag、上传和 GitHub Release 必须另获明确授权。

## 实施工作流

1. 确认变更范围和当前 dirty tree，保留用户无关修改。
2. 故障先采证据并定位根因；功能或修复优先写能真实失败的最小测试。
3. 在 Windows 构建机运行定向测试，再按风险扩大到项目或 solution Release 构建。
4. 每个阶段结束前单独回答：是否引入未被需求使用的抽象、状态、测试或发布分支？若是，先删除再进入下一阶段。
5. 运行 `git diff --check`，明确动态验证、环境跳过和未验证项。
6. 按授权分 Task 本地提交，使用 `type: 中文概括`，不添加 AI 署名。

## 发布门禁

### 本地开发配置与构建流程

1. 首次使用将 `development.sample.json` 复制为 `development.local.json`，限制为当前用户可读写（macOS/Linux 使用 `chmod 600`）。分别填写 `build` 和 `signing` 的 `host`、`sshUser`、`sshIdentityFile`；两处 key 路径均属于发起 SSH 的开发电脑，可分别配置。`build` 下其余路径属于 Windows 构建机。
2. `signing.baseUrl` 使用签名服务的内网 IP 和实际监听端口；直连服务不带公网代理的 `/sign` 前缀。将用户提供的 token 文本去除首尾空白后写入 `signing.bearerToken`，不保存 token 文件路径。复制和使用凭证时仅由程序读取，不输出内容。
3. 根据当次任务确定版本，在构建机的 `build.workspaceParent` 下按 `build.repositoryDirectoryTemplate` 准备完整历史、干净的源码。用 `build.sshIdentityFile` 连接 `build.host` / `build.sshUser`；将 `build.gitExecutable` 所在目录加入 PATH，并按需用 `build.pythonExecutable` 设置 `UV_PYTHON`。需要 SSH 检查签名机时，使用 `signing.host`、`signing.sshUser` 和 `signing.sshIdentityFile`，签名 API 仍使用 `signing.baseUrl`。
4. 现有构建脚本不会自动加载 JSON。开发操作读取配置后，先检查 `signing.baseUrl` 的 `/health/live`；通过 SSH 标准输入将 `signing.bearerToken` 写入构建机随机临时目录内的文件，ACL 仅允许构建账户和 SYSTEM，禁止将 token 拼进命令行。
5. 调用下面的包装器：`SigningBaseUrl` 对应 `signing.baseUrl`，`BearerTokenPath` 使用远端临时文件路径，`SigningReferencePath`、`DotnetRoot`、`UvPath` 分别对应 `build.signingReferencePath`、`build.dotnetRoot`、`build.uvExecutable`。无论成功失败，都在 `finally` 删除远端临时凭证文件和目录。
6. 完成下述安装包验证后汇报结果。配置不设默认交付机器或目录；只有当次任务明确要求交付时才传输安装包。

在完整、干净、非 shallow 的仓库先运行：

```powershell
.\scripts\pre-release-check.ps1
```

本地签名构建优先复用无凭据包装器：

```powershell
.\scripts\build-local-signed-release.ps1 `
  -Version <semver> `
  -SigningBaseUrl <user-configured-http-or-https-url> `
  -BearerTokenPath <protected-token-file> `
  -SigningReferencePath <known-good-signed-file> `
  -DotnetRoot <dotnet-root> `
  -UvPath <uv.exe>
```

构建结束必须证明：

- `artifacts/release` 精确只有主程序 Setup，以及判定需要发布时的 PDF Setup，
  共 1 或 2 个 EXE；判定记录位于当前版本 build 目录。
- 所有生成的安装包 Authenticode 有效、发布者与参考签名一致，并有有效时间戳。
- PDF 判定依赖完整 Git 历史，且有效输入路径的工作树必须干净；有效输入未变化时仍通过
  helper 测试与冻结验证，但不得签名、打包或上传 PDF。需要发布时 helper 版本必须等于主程序版本。
- 主安装包不会混入 PDF helper；PDF 扩展安装包包含并校验 helper。
- 构建、签名、发布是不同状态；没有真实签名证据时不得称“可发布”。

## 发布验证机门禁

1. 安装主 Setup，确认安装进度真实、公共桌面快捷方式存在，然后重启。
2. 登录 Administrator，确认 Service、签名用户 Agent 和 SimplySign 位于正确会话；进程存在不是 ready 证据。
3. 导入完整 `otpauth://` 激活内容，点击登录；只输出稳定错误码或脱敏状态。
4. 调本机 `/v1/health/ready`，再签一个新生成、未预签名的 PE；要求目标证书序列号、Authenticode 和 `signtool verify /pa /all` 都通过。
5. 如验证 PDF，再独立安装 PDF Setup，确认扩展校验通过后签一个新 PDF；未安装扩展时代码签名仍应完整 ready。
6. 验证卸载的幂等、精确所有权和残留；不得清理未知文件。

## 汇报格式

按“代码/测试、构建、签名、安装、真实签名、未验证项”分开报告。列出提交号和门禁结果，但不暴露凭据、内部完整证书身份或 secret-bearing 路径。
