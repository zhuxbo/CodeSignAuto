# SimplySignAuto 智能体入口

- 始终使用中文；开始实质工作前先读 `.agents/skills/simplysignauto-release/SKILL.md`。
- 以 `README.md`、`docs/API.md` 和当前生产代码为产品事实，不从 `.superpowers/` 过程记录反推现状。
- 主程序默认提供代码签名；PDF 是独立安装的可选扩展。产品 HTTP API 不内建 HTTPS，TLS 由用户配置的外部代理负责。
- Windows 构建机用于编译和测试；发布验证机只安装与验收，禁止在验证机构建。主机映射保留在本地配置中，不写入仓库。优先 SSH/脚本，必要时才操作桌面。
- 不读取、输出、提交或记录 Bearer token、TOTP、`otpauth` secret、私钥、RDP 密码或带凭据 URI。
- 每个 Task 只做范围内最小实现，验证后回看是否过度设计；按用户授权可分 Task 本地提交，推送、tag 和 GitHub Release 仍需单独授权。
- 过程文档放 `.superpowers/` 且不提交；新增用户文档只在使用方式、接口、部署或架构变化时维护。
