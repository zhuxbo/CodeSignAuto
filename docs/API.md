# SimplySignAuto HTTP API

本文档描述 SimplySignAuto 当前公开的 HTTP 签名接口。产品本身不提供 HTTPS、证书导入或证书自动更新；需要 HTTPS 时，由部署者在产品外配置反向代理，并把请求转发到 SimplySignAuto 的 HTTP 监听端口。

## 基本约定

- 默认地址：`http://<server>:7080`
- API 版本前缀：`/v1`
- 除 `GET /health/live` 外，所有接口都要求 Bearer token。
- 请求和响应 JSON 使用 UTF-8、camelCase 字段名和严格 schema。未知字段、重复字段、错误大小写或错误类型都会被拒绝。
- 文件上传上限为 512 MiB；`parameters` 上限为 64 KiB。
- 服务只接受 multipart 表单上传，不接受服务器本地文件路径或远程 URL。
- 响应不会包含内部路径、Windows SID、连接 ID、命令行、请求头或激活 secret。

安装成功后，一次性明文 token 位于：

```text
%ProgramData%\SimplySignAuto\install-token.txt
```

把 token 复制到调用方的 secret store 并确认 API 可访问后，应删除该文件。服务端只保存 token 的 SHA-256。

以下示例使用：

```bash
BASE_URL=http://signer.internal:7080
TOKEN='从 secret store 注入，不要写入仓库'
```

如果 `BASE_URL` 是用户配置的 HTTPS 反向代理地址，客户端仍必须正常校验证书和 hostname，不要使用 `curl -k`。

## 接口一览

| 方法 | 路径 | 认证 | 说明 |
| --- | --- | --- | --- |
| `GET` | `/health/live` | 否 | SQLite liveness |
| `GET` | `/v1/health/ready` | Bearer | 当前签名能力 readiness |
| `POST` | `/v1/jobs` | Bearer | 异步提交签名任务 |
| `POST` | `/v1/sign?waitSeconds=120` | Bearer | 最多等待 1–120 秒的同步调用 |
| `GET` | `/v1/jobs/{jobId}` | Bearer | 查询任务状态 |
| `GET` | `/v1/jobs/{jobId}/result` | Bearer | 下载已完成结果 |

当前没有取消任务、列出证书或让服务读取任意本地路径的 HTTP 接口。证书序列号从管理员控制台“激活凭证”页获取。

## 认证

请求头必须只有一个规范 Bearer 值：

```http
Authorization: Bearer <token>
```

缺失、重复、使用其他 scheme 或 token 不匹配均返回 `401`。不要把 token 放入 URL、命令行历史、日志或错误报告。

## 提交任务

### 异步提交

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: build-20260818-app-x64' \
  -F 'file=@./app.exe;type=application/octet-stream' \
  -F 'parameters={"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","appendSignature":false}' \
  "$BASE_URL/v1/jobs"
```

成功返回 `202 Accepted`：

```json
{
  "jobId": "00000000-0000-0000-0000-000000000000",
  "state": "queued",
  "statusUrl": "/v1/jobs/00000000-0000-0000-0000-000000000000",
  "resultUrl": "/v1/jobs/00000000-0000-0000-0000-000000000000/result",
  "expiresAt": "2026-08-19T10:00:00+00:00"
}
```

### 最多等待 120 秒

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: invoice-20260818-42' \
  -F 'file=@./invoice.pdf;type=application/pdf' \
  -F 'parameters={"kind":"pdf","certificateSerialNumber":"6F09D233","digestAlgorithm":"sha256","page":1,"box":[36,36,220,110],"fieldName":"Signature1","reason":"Approved","location":"Shanghai"}' \
  -o invoice.signed.pdf \
  "$BASE_URL/v1/sign?waitSeconds=120"
```

`waitSeconds` 必须为 1–120，默认 120：

- 在窗口内成功：`200`，响应体是签名文件。
- 在窗口内失败：返回 problem JSON。
- 到时仍未完成：`202`，返回与异步提交相同的任务对象；任务继续运行，不会被取消。

调用方必须先检查 HTTP 状态和 `Content-Type`，不能把 `202` 或 problem JSON 当成签名文件保存。

## multipart 约束

表单必须恰好包含：

- `file`：一个文件，文件名 1–255 字符；不得包含路径、控制字符、`:`、`/` 或 `\`。
- `parameters`：一个 UTF-8 JSON 对象。

两个 part 的先后顺序不限。额外、重复或缺失 part 会返回 `invalid_parameters`。服务会同时核对扩展名和文件 magic，不只信任上传文件名。

服务只接受当前 Agent 会话中对应签名能力已就绪的请求。空闲会话不做后台保活；如果
Agent 连接和 heartbeat 仍有效，但 SimplySign 进程或对应能力处于需要登录状态，服务会
在写入 spool 和创建任务前通过 Agent 控制通道发起一次登录，并发请求共享同一次进行中的
登录。登录失败、连接断开、heartbeat 过期或登录后能力仍未就绪时返回
`503 service_unavailable`，且不创建任务、不保留上传文件；PDF 扩展缺失或校验失败时
分别返回 `pdf_support_not_installed` 或 `pdf_helper_tampered`。能够在入队前确定的
参数结构、文件类型和证书错误会直接返回 problem JSON，不创建任务，也不留下
spool 文件。`parameters` part 位于文件前时，这些错误会在读取文件内容前返回。

可选 `Idempotency-Key` 请求头为 1–128 个可打印 ASCII 字符。相同 token、相同 key 和相同请求返回原任务；同 key 对应不同请求返回 `409 idempotency_conflict`。

## Authenticode 参数

支持 `.exe`、`.dll`、`.msi`、`.sys` 和 `.cat`：

```json
{
  "kind": "authenticode",
  "certificateSerialNumber": "52A1B4C9",
  "digestAlgorithm": "sha256",
  "appendSignature": false
}
```

- `certificateSerialNumber`：规范化十六进制 X.509 序列号。
- `digestAlgorithm`：当前只允许 `sha256`。
- `appendSignature`：是否追加签名；`false` 时已签文件会按既有策略拒绝。

请求不能指定 SignTool 路径、TSA URL、进程参数或服务器文件路径。

## PDF 参数

PDF 扩展包安装且文档签名证书可用时支持：

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

- `page`：1–10000。
- `box`：`[left,bottom,right,top]`，四个有限数字，必须满足 `left < right`、`bottom < top`。
- `fieldName`：1–64 字符，以 ASCII 字母开头，只允许字母、数字、`_`、`.`、`-`。
- `reason`、`location`：可省略，最多 128 字符，不允许控制字符。

PDF 扩展与主程序独立发布；扩展未安装时 Authenticode API 仍可正常使用。

## 查询状态

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/v1/jobs/00000000-0000-0000-0000-000000000000"
```

成功返回：

```json
{
  "jobId": "00000000-0000-0000-0000-000000000000",
  "state": "succeeded",
  "originalName": "app.exe",
  "inputSha256": "...",
  "resultSha256": "...",
  "errorCode": null,
  "errorMessage": null,
  "createdAt": "2026-08-18T10:00:00+00:00",
  "startedAt": "2026-08-18T10:00:01+00:00",
  "completedAt": "2026-08-18T10:00:03+00:00",
  "expiresAt": "2026-08-19T10:00:00+00:00"
}
```

`state` 可能为：`queued`、`waiting_for_agent`、`signing`、`verifying`、`succeeded`、`failed`、`expired`。

## 下载结果

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -o app.signed.exe \
  "$BASE_URL/v1/jobs/00000000-0000-0000-0000-000000000000/result"
```

- `succeeded`：`200` 文件流，下载名为 `<stem>.signed.<ext>`。
- 未完成：`409 job_not_complete`。
- 已过期：`410 job_expired`。
- 文件完整性校验失败：`500 result_corrupt`，服务会防御性地把任务标记为失败。
- 不支持 HTTP Range。

调用方应校验下载长度，并与状态对象中的 `resultSha256` 比对。

## 健康检查

```bash
curl --fail-with-body "$BASE_URL/health/live"
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/v1/health/ready"
```

- `/health/live` 匿名，只证明服务进程和 SQLite 健康；成功返回 `{"status":"live"}`。
- `/v1/health/ready` 需要 Bearer；只有 Agent 当前连接、会话、heartbeat、SimplySign、token、证书和私钥均满足当前已配置能力时才返回 `200`，否则返回 `503`。
- liveness 为 `200` 不代表签名已就绪。自动化调用应以 readiness 和具体任务结果为准。

## problem JSON

错误响应使用 `application/problem+json`：

```json
{
  "type": "about:blank",
  "title": "The request is invalid.",
  "status": 400,
  "code": "invalid_parameters",
  "correlationId": "0H...",
  "jobId": null
}
```

常见错误码：

- 请求：`invalid_parameters`、`unsupported_type`、`file_signature_mismatch`、`file_too_large`、`idempotency_conflict`。
- 任务：`job_not_found`、`job_not_complete`、`job_expired`、`result_corrupt`。
- Agent：`agent_unavailable`、`agent_session_zero`、`agent_wrong_user`、`agent_protocol_mismatch`。
- 证书：`certificate_catalog_unavailable`、`certificate_not_found`、`certificate_serial_ambiguous`、`certificate_not_usable`。
- SimplySign：`otp_missing`、`clock_not_synchronized`、`simplysign_login_failed`、`token_missing`、`certificate_missing`、`private_key_missing`、`pkcs11_session_lost`。
- Authenticode：`signtool_missing`、`invalid_signable_file`、`already_signed`、`authenticode_sign_failed`、`authenticode_verify_failed`。
- PDF：`pdf_support_not_installed`、`pdf_helper_tampered`、`pdf_invalid`、`pdf_sign_failed`、`pdf_appearance_font_missing`、`pdf_verify_failed`。
- 服务：`spool_write_failed`、`input_corrupt`、`service_unavailable`、`internal_error`。

入队前已能确认的 `certificate_not_found`、`certificate_serial_ambiguous` 和
`certificate_not_usable` 返回 HTTP 400；证书目录不可用返回 HTTP 503。以上错误
不会生成一个随后必然失败的任务。

`correlationId` 用于关联本机诊断，但不会暴露内部路径或 secret。调用方应根据稳定 `code` 分支，不要解析英文 `title`。

## 重试建议

- 上传连接中断或 `/v1/sign` 超时时，使用相同 `Idempotency-Key` 重试，不要生成第二个任务。
- `202` 后轮询 `statusUrl`；建议指数退避并设置调用方总时限。
- `waiting_for_agent` 不表示任务失败；Agent 恢复后队列会继续。
- `failed`、`expired`、`result_corrupt` 是终态，不应无限重试同一 job ID。
- token 轮换后旧 token 立即失效；调用方 secret store 应原子切换。
