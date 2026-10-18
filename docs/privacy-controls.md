# Desktop / CLI 遥测控制

本文把固定遥测审计中的 Desktop 与 Claude Code CLI 控制接入 Guard 的纯策略层。`guard_privacy.rs` 只生成子进程环境补丁和诊断结论；独立的只读适配器会读取有限的版本元数据和受管配置字段。它不会写配置或系统设置、读取身份/网络/凭据，也不会启动应用。OTLP endpoint 只用于判断是否配置，不会被输出或记录；本地解析仍会短暂读取该字段值。

## 诊断语义

渠道状态只有三种：`configured_off` 表示已读回的配置意图要求关闭，`open` 表示配置允许该渠道，`unknown` 表示输入不足或该路径不受当前控制覆盖。版本范围另报 `audit_version`、`candidate_version` 或 `unknown_version`。报告包含 `runtimeVerified=false`；它不会输出“无遥测”或“系统保护已验收”。

Rust 接口：

```rust
cli_environment_patch() -> &'static [EnvironmentEdit]
diagnose_cli(CliReadback) -> CliPrivacyReport
diagnose_desktop(DesktopReadback) -> DesktopPrivacyReport
```

`EnvironmentEdit.value = Some(...)` 表示只给一个 Guard 子进程设置该键；`None` 表示只从该子进程环境移除该键。调用方要在合并 inherited/host 环境之后应用补丁，保留其余环境与凭据；不得调用 `std::env::set_var`。诊断输入是调用方已经解析好的布尔值和 presence-only 事实，模块不接受或返回原始环境、版本字符串、端点或头值。

## Claude Code CLI

审计源为 CLI 2.1.283：[`telemetry/cli.md`](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/telemetry/cli.md) 与 Desktop/CLI 联动结论 [`telemetry/linked.md`](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/telemetry/linked.md)。模块给 Guard 直接启动的 CLI 子进程返回以下最小覆盖：

| 控制 | 补丁意图 |
|---|---|
| A/B/C/E/G（第一方事件、Datadog、内部指标、GrowthBook） | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` |
| D（用户配置的 OTel） | `CLAUDE_CODE_ENABLE_TELEMETRY=false`；logs、metrics、traces 与 `ANT_OTEL_LOGS_EXPORTER` exporter 设为 `none` |
| OTel 内容粒度 | prompts、assistant responses、tool content/details、managed settings 与 raw API bodies 全部设为 `false` |
| Beta tracing | 关闭 detailed/enhanced tracing 标志并从子进程移除 `BETA_TRACING_ENDPOINT` |
| 模型提示词的数据最小化 | `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS=1`，移除 system prompt 的 gitStatus 段（分支、文件名、近期提交、Git author/email）；这是上下文缩减，不是遥测关闭 |

其余启动环境，包括凭据和 OTLP headers，保留原值；禁用 exporter 后诊断不会读取这些值。Git 提示词段由候选补丁单独缩减。模型请求仍会发出，并可能携带 `metadata.user_id` 中的 device/account/session 标识、cwd/home 路径及其他 prompt 内容。远程/网关 OTLP relay（F2）依赖会话运行时上下文，模块不会删除这些变量以免破坏远程会话；诊断会单独报告该通道的 `open`、`configured_off` 或 `unknown`，只有 presence-only 读回确认条件不存在时才报 `configured_off`。

CLI 版本必须单独读回。固定审计版本是 2.1.283；当前安装链接指向 2.1.296，因此按候选版本处理，不能把审计结论升级成同版本验证。通过 Claude Desktop 管理的 CLI 子进程由宿主在继承环境之后组合 CCD 与 OTLP 变量；这类启动来源以及来源未知的路径，诊断会把受宿主覆盖的渠道置为 `unknown`。父代理应在实际 spawn 的最后一步应用补丁，或保留候选状态。

## Claude Desktop

固定静态审计对象是 macOS Desktop 2.9939.2：[`telemetry/desktop.md`](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/telemetry/desktop.md)。配置职责分开：

| 读回项 | 控制渠道 | 审计范围 |
|---|---|---|
| `disableEssentialTelemetry=true` | Sentry 错误/崩溃上报与 Datadog RUM | 仅 3p |
| `disableNonessentialTelemetry=true` | 一方产品事件、诊断包上传与 Segment | 仅 3p；第一方 CoworkSessionDeletionEvent 是独立通道 |
| `disableAutoUpdates=true` | 自动更新检查 | 1p 与 3p；遥测键不控制它 |
| `otlpEndpoint` 未配置，或 `otlpDesktopLogLevel=off` | Desktop 与其 CLI 子进程的企业 OTLP 导出 | endpoint 存在时 Desktop 可向 CLI spawn 注入 OTLP variables；不是 3p telemetry toggle 的覆盖 |

纯策略接口只有在版本与部署模式已知时才能推导这些状态。但当前 `guard_privacy_readback::compose()` 始终传入 `DesktopDeployment::Unknown`，CLI 始终传入 `CliLaunchOrigin::Unknown` 且所有 CLI 控制读回为 `None`；因此当前 `guard_privacy_inspect` 的 Desktop 渠道和 CLI 控制渠道实际全部是 `unknown`，仅 `cli_model_requests` 报 `open`。fixture 模拟 `configured_off` 不代表当前适配器能读出它。

我只对当前安装包做了开关点检：`/Applications/Claude.app/Contents/Info.plist` 显示 2.110.0；静态读取 `Contents/Resources/app.asar` 可见两个遥测键仍登记为 3p scope、`disableAutoUpdates` 登记为 1p/3p、`otlpEndpoint` 为 3p，并可见相应的设置映射和局部调用点。这只证明开关名称和部分 schema/调用仍存在；不是对 2.110.0 的完整审计、所有出站路径复验或运行时控制验证。Windows 目前也没有 Claude Desktop/CLI 版本适配器：Desktop bundle 路径是 macOS `/Applications/Claude.app/Contents/Info.plist`，CLI 版本查找使用 `~/.local/bin/claude`，不能发现常见 Windows 安装。模块因此只按 2.9939.2 作 audit-version 判断。

`disableNonessentialServices` 可关 connector favicon、Artifact preview 与 MCP Apps iframe，但 dictation host 动态且不受此开关控制；3p model-catalog 会以 omit credentials 轮询 `downloads.claude.ai`，也不是上述遥测开关能说明的事件流。Cowork 本地诊断包导出仍会产生事件；Sentry minidump 可带原始附件。`CI=1` 虽会影响审计版的部分上报，但它是通用变量且会改变其他程序行为，Guard 不设置它。模块不删除 `ant-did`、CLI `userID` 或其他身份数据。

## 接入边界与离线检查

`mod guard_privacy;` 与只读检查命令已注册到 Tauri host。当前 Mac `LegacyApplicationSupervisor.launch` 通过 NSWorkspace 启动 Claude Desktop，只设 arguments；它不创建 Desktop 内部的 CLI 子进程。已编译的 `ManagedLaunchCandidate` 没有生产调用点。Windows `guard_windows_launch` 也未接入 Guard executor。故 `cli_environment_patch()` 目前只在策略与候选测试中生效，不会覆盖用户独立启动的 CLI 或 Desktop 管理的 CLI，也不会因 TUN 状态自动应用。Desktop 托管配置只能由只读适配器读取，本模块不写 MDM、GPO 或 managed settings。

模块包含纯策略单测。Rust 语法与测试目标 metadata 离线编译通过；运行测试二进制时，系统链接器因当前 Xcode license 未接受而退出，本任务没有修改系统许可状态。编译和单测均不验证安装进程的实际出站行为。
