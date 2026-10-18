# 三方保护能力原子目录与 Guard 对照

## 范围与判断方式

本目录把“来源里有这项能力”和“Guard 已能执行这项能力”分开记录。Android 不纳入。CCBaga 是网络配置、浏览器与身份工具；`claude-telemetry-audit` 是特定版本的外发行为审计，提供控制点和风险证据，本身不拦流量。两者不能仅凭源码或审计结论推导成 Guard 已生效。

来源固定为 Guard/CCBaga 工作区基线 `aff6122719c479effd4d53c7d875bcc3c04edcc8`、上游 CCBaga 快照 `a3a663a30add6cb4c3065a3e9ddb470141d181af`、遥测审计快照 `bf1fa2075050e67cc3db10155c193ff1e08a0569`。本轮对网络 Skill 的改动与上游快照分开识别。遥测审计只适用于 macOS Desktop 2.9939.2 和 CLI 2.1.283；本机 Desktop 2.110.0、CLI 2.1.296，因此 Guard 对有效策略只报 `unknown`。

状态标记：

- **接入（离线）**：代码及隔离 fixture 覆盖；尚不代表目标机上的实际进程或流量。
- **候选（关闭）**：有候选实现，但未接入已登记的生产执行规则；目标必须继续显示 unavailable。
- **部分**：只读诊断或局部控制存在，执行来源、版本或覆盖面不足。
- **缺失／待验**：尚无 Guard 控制，或缺真实系统证据。

## CCBaga 原子能力

下表的 C 项以 CCBaga 上游快照的代码和文档为能力来源；最右栏核对 Guard 本轮状态。已有浏览器设置不等于已由 Guard 受管启动，网络配置也不等于 TUN 中断时系统仍拒绝直连。

| ID | CCBaga 能力 | Guard 逐项状态 |
| --- | --- | --- |
| C01 | 选择固定 Static ISP / 住宅 SOCKS5 出口 | Guard 定义固定出口模式；真实住宅出口未接入、未验。 |
| C02 | 客户端经 VLESS/Reality/Vision TCP 443 到 VPS，再经认证 SOCKS5 出口 | 服务端配置被保留；Guard 没有运行或验证该链路。 |
| C03 | 代理绑定的 VPS TCP 没有直连 fallback | 候选策略遵循 fail-closed；系统路由未部署，未验证掉线时是否旁路。 |
| C04 | Network Skill helper 默认清除 VPS Stripe 直连例外 | 本轮 Skill helper 显式传空直连名单并通过离线测试；无 VPS 验证。裸脚本保留历史默认，且现在要求 staged wrapper 才能进入部署。 |
| C05 | VPS 阻断 UDP | 已列共同验收项；Guard/WFP/LuLu 规则未写入，未验证 UDP。 |
| C06 | VPS 阻断 private/LAN 目标 | 配置可生成；无真实规则仲裁与旁路验收。 |
| C07 | VPS 阻断 BitTorrent | 配置可生成；无 VPS 验证。 |
| C08 | AI 域名组只提供代理节点或 REJECT，不提供 DIRECT | 源配置有此设计；尚未导入真实客户端验证。 |
| C09 | 客户端默认目的地只走节点或 REJECT | 与固定出口目标相符；Guard 的实际客户端路由仍 unavailable。 |
| C10 | TUN 自动路由、DNS 53 劫持、客户端关闭 IPv6 | Guard 计划按目标管理协议族；系统级 TUN/WFP/LuLu 没有验收。 |
| C11 | Fake-IP DNS；AI 域名 DoH 走 AI 代理组、普通 DoH 走代理组；国内域名和 bootstrap DNS 有直连例外 | Guard 尚未读取并验证实际 resolver 路径；所有直连例外必须作为显式策略显示。 |
| C12 | 操作流程要求 TUN 开、System Proxy 关、CCBaga Browser 显式代理留空 | Guard 未替用户改 TUN/系统代理；设置需逐项验收，不能自动接管全机。 |
| C13 | CCBaga Browser 禁止非代理 WebRTC UDP | Browser 配置中保留相关选项并有配置测试；Browser 的 Guard handoff 和实际 ICE 结果待验。 |
| C14 | CCBaga Browser 关闭 QUIC | 源配置保留；实际启动与网络效果未验。 |
| C15 | Browser 使用 SOCKS 时通过 host-resolver-rules 防普通本地 DNS，允许代理主机和 loopback 例外 | 源配置保留；Guard 尚未证明 browser DNS 与系统 DNS 均走预定路径。 |
| C16 | Browser 拒绝地理定位，包括普通与近似/精确 API；清除既有授权例外 | 配置与临时 profile fixture 覆盖；未检查真实 Browser profile。 |
| C17 | 地区设置可对齐语言、locale、时区并导航系统定位设置 | Guard 保留设置页；本轮未修改用户或系统值。它不改变公网 IP，也不证明地理位置不可推断。 |
| C18 | 独立 Chromium profile；每身份不应共享 Cookie 和站点状态 | CCBaga 身份联动升级为身份到 profile slot/seed 的绑定和 pending/rollback；SQLite 和虚构资料 fixture 通过。真实 Chromium profile 内容与 Cookie 不在 `.baga` 加密身份归档里，也未访问。 |
| C19 | 稳定 fingerprint seed，可单独轮换；地区/语言/时区按配置；平台和硬件参数部分取真实设备值 | Guard 保留可配置项并加身份 seed；没有运行浏览器。轮换 seed 不等于清 Cookie/站点状态，也不隐藏真实硬件特征。 |
| C20 | Canvas/layout 等可使用稳定种子或真实设备参数；字体、GPU、音频信息可保留真实值 | 没有新增匿名保证；真实硬件参数仍是可能的识别面。 |
| C21 | 清理专用 profile 的缓存和 Crashpad 报告 | 清理操作沿用 CCBaga；Guard 增加锁定/操作协调，但本轮没有执行真实清理。 |
| C22 | 单独清理 cookies、local/session storage、IndexedDB、Service Worker、Sessions 等 | 作为用户可选身份/站点清理保留；不会因轮换 seed 或切换账号自动执行。 |
| C23 | Browser 的代理配置不保存用户名密码，认证交给本机代理客户端 | 源设计保留；Guard 未读取或迁移用户代理凭据。 |
| C24 | 校验 PEM/PPK/PUB 密钥组匹配，限制私钥权限，失败停止 | 本轮网络 Skill 离线校验覆盖；未读取用户密钥或连接服务器。 |
| C25 | SSH 首次连接需核对主机指纹，后续严格校验、变化时停止，禁用密码/Agent 认证 | CCBaga 原有 TOFU 流程在本轮升级为先列候选 SHA256，再与供应商控制台人工核对后才写专用 pin；改动通过离线测试，未连接真实主机。 |
| C26 | 私有连接配置/订阅仅当前用户可读；拒绝链接路径、Git/共享目录和覆盖已有配置 | 本轮 Python helper 检查与 15 项离线测试通过；真实 Windows ACL 与用户目录未验。 |
| C27 | 敏感字段走 stdin/SSH，不放 argv、shell history 或公开日志；不使用在线订阅转换站、不收集浏览历史 | 本地源码保留并修正脱敏输出；没有运行真实部署。 |
| C28 | 优先通过 SSH 私下取回订阅 YAML，避免公网上的订阅链接暴露凭据 | Skill 路径保留；HTTP 8443 token URL 仍存在，使用时须优先 SSH 文件交付。 |
| C29 | 部署前核对目标系统、SSH 身份、预计 SOCKS 出口及现有服务/配置冲突 | 本轮新增固定脱敏快照；未知状态、未标记遗留配置和冲突均停止。只做过 fixture，没有检查 VPS。 |
| C30 | 部署需明示目标变更并经用户确认；失败可能留下部分服务/防火墙变化 | Skill 流程保留；`setup-vps.sh` 新增 staged wrapper 标记，裸调用拒绝；未实际部署。 |
| C31 | VPS 使用 key-only SSH，限制 root/SSH 认证与暴力尝试面，先测试配置再 reload | 配置模板存在；无服务端验收。 |
| C32 | fail2ban SSH jail | 配置模板存在；未在 VPS 启动或测试。 |
| C33 | UFW 默认拒绝入站，只开放明示的 SSH、Xray 和可选订阅端口 | 配置模板存在；云供应商 ACL、全部现存规则和 IPv6 行为未检查。 |
| C34 | 安全更新由 unattended-upgrades 安装，避免自动重启 | 配置模板存在；未确认生产主机的计划状态。 |
| C35 | Xray 密钥文件按 root/service-group 权限保存；订阅服务无特权并使用 systemd sandbox | 配置模板存在；无主机权限/服务运行证据。 |
| C36 | 部署后检查服务、配置，并用新 SSH 会话复核；配置通过 SSH 私下下载 | 离线脚本检查存在；本轮没有远程执行。 |
| C37 | `tun-check` 忽略代理环境变量，检查系统路由出口 | 命令实现保留；没有连接真实 TUN。它只测 CLI 路径。 |
| C38 | 比较机器、Browser 与出口 IP/国家、时区、语言、平台/CPU/版本、定位状态；失败/不一致不得显示绿色 | CCBaga 诊断页保留，Guard 不把探针结果当网络许可。出口查询会联系第三方服务并暴露请求 IP；没有真实出口运行证据。 |
| C39 | DNS、WebRTC 与图形字体需独立实测，普通出口 IP 结果不足以证明无泄漏 | Guard 验收清单已列独立项；尚无真实 DNS/WebRTC 证据。 |
| C40 | Claude Desktop/CLI 身份归档、空身份、恢复与可选共享数据范围 | 身份切换事务已有离线覆盖；未读写真实账号/档案。 |
| C41 | `.baga` 身份归档用 AES-256-GCM 与每档密钥；归档验证后才替换工作区 | CCBaga 身份归档加密与校验逻辑保留；Browser profile/Cookie 不属于此加密归档。本轮使用虚构数据 fixture，未访问真实归档。 |
| C42 | 切换失败可回滚，pending 状态可恢复；用户控制保留数据，不扫描外部项目源码 | Guard 新增身份到 profile slot/seed 的事务和恢复检查；23 项身份测试通过，真实用户数据未动。 |
| C43 | 本地 cleaner 可处理 `ant-did`、`ant-device-registry.json` 等身份关联目标 | 本机目标可随用户选择的身份清理/切换；不会删除 Anthropic 服务端设备记录，Guard 不自动重置安装 ID。 |
| C44 | CCBaga 还提供 Linux x86_64 应用和网络入口；TUN 或显式 Browser proxy 可用，但 GNOME/KDE proxy 与 PAC 不独立发现，Linux ARM 不在当前 pinned browser 支持范围 | Linux 来源能力保留在目录；按 Fox 最新决定暂不实施 Guard Linux backend。本轮只做 Mac，Windows 留文档并待移交 Windows 主机。 |

### CCBaga 的检测项与不能继承为保证的边界

1. 机器或 Browser 显示出口匹配，是当次观察，不是持续 kill switch。
2. helper 的 TUN 检查不使用代理环境变量，但只验证 CLI 当次系统路线；不能替代 Browser、DNS、WebRTC 与 IPv6/UDP 测试。
3. Browser 环境页不独立探测 DNS/WebRTC；green 状态不可升级成无泄漏结论。
4. 国内域名和 bootstrap DNS 会直连；原始上游默认还有 Stripe 直连名单。本轮 Skill helper 改为清空名单，独立运行脚本默认仍可见旧值；直接脚本运行现在被 staged 标记挡住。
5. Mihomo TUN 是全机路由语义；若使用其默认路由，可能把 Codex、Obsidian 等非目标流量一并代理。Guard 的目标范围是按目标进程隔离。
6. 配置没有给出 OS 级 TUN 故障 kill switch 证据；必须验证客户端崩溃、断连和现有 TCP/UDP 连接。
7. 指纹轮换不清 Cookie、账号登录态、站点存储或真实平台/CPU 特征。
8. 公开订阅端口仍是 HTTP 8443，路径 token 是凭据而非加密；优先 SSH 下载本地订阅文件。
9. IP 诊断会联系外部回显服务；必须将测量请求作为一次可见外发，而不是零流量检查。

来源：上游 [Network Skill README](../../evidence/protection-union-20261014/sources/CCBaga/skills/ccbaga-network/README.md)、[Network Skill](../../evidence/protection-union-20261014/sources/CCBaga/skills/ccbaga-network/SKILL.md)、[server setup](../../evidence/protection-union-20261014/sources/CCBaga/skills/ccbaga-network/scripts/setup-vps.sh)、[Browser config](../../evidence/protection-union-20261014/sources/CCBaga/src-tauri/src/browser/config.rs)、[Browser profile](../../evidence/protection-union-20261014/sources/CCBaga/src-tauri/src/browser/profile.rs)、[identity storage](../../evidence/protection-union-20261014/sources/CCBaga/docs/identity-storage.md)。

## telemetry audit 控制与残余外发面

T 项是审计快照提出或记录的可用控制。`claude-telemetry-audit` 本身不应用这些开关。Guard 的 CLI 环境策略已实现为子进程补丁；由于候选尚未登记/启用，其结果仍是离线候选。Desktop 配置只读，未写 MDM、GPO 或应用设置。

| ID | 审计发现的控制或建议 | Guard 逐项状态 |
| --- | --- | --- |
| T01 | Desktop `disableEssentialTelemetry=true` 关闭 Sentry 错误/崩溃上报与 Datadog RUM（BYOK/3p scope） | 只读检查已接入；当前适配器把部署模式硬编码为 unknown，所以所有 Desktop 控制渠道实际都 unknown；没有托管配置写入。 |
| T02 | Desktop `disableNonessentialTelemetry=true` 关闭一方产品事件、诊断包上传与 Segment（BYOK/3p scope） | 同 T01；第一方 CoworkSessionDeletionEvent 另列，当前无运行时证明。 |
| T03 | Desktop `disableAutoUpdates=true` 单独关闭更新检查，遥测键不控制更新 | Guard fork 的自身自动更新关闭；没有改 Claude Desktop 更新设置。 |
| T04 | Desktop 留空 `otlpEndpoint`；若 collector 已配置，另将 `otlpDesktopLogLevel=off` | 只读检查 endpoint 是否存在；不读取原值、不写配置，实际渠道仍 unknown。endpoint 可使 Desktop 给 child CLI 注入 OTLP exporter、endpoint、header 与 tracing flags。 |
| T05 | Desktop 单进程 `CI=1` 可关部分备用初始化/产品事件 | Guard 不全局设置 CI；尚无 Desktop 专用进程级接线。 |
| T06 | Desktop `disableNonessentialServices=true` 关闭 favicon、Artifact 预览、MCP App iframe 等服务 | 未自动设置；会影响产品功能，应作为独立可选项并说明后果。 |
| T07 | Desktop 按进程/端点限制 `*.ingest.us.sentry.io`、`claude.ai/api/event_logging/*`、`api.anthropic.com/api/desktop/*/update`、`releases.claude.com`、`downloads.claude.ai`；可选服务还涉及 Segment、Datadog RUM、favicon、Artifact/MCP iframe | Guard 有目标级策略设计，尚未登记规则；普通 host firewall 不能把 HTTPS URL path 当成独立规则。不要整域阻断 Anthropic 推理。 |
| T08 | Desktop 可使用托管 `egressProxyUrl`/PAC 固定 Chromium 网络栈代理，可能覆盖 OS 代理 | Guard 未写托管代理或 PAC；当前真实 Desktop 路由未知。 |
| T09 | Desktop 可删除 `ant-did` 及私有目录中的派生安装 ID 以重置关联 | Guard 不自动删此类标识；未实现破坏性清理操作。 |
| T10 | Desktop 可通过 `CLAUDE_USER_DATA_DIR` 指向独立 userData | Guard 未设置该变量；身份/profile 隔离尚未与 Claude Desktop 私有目录相接。 |
| T11 | CLI `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 关闭一方事件、GrowthBook/配置拉取和内部指标；`DISABLE_TELEMETRY=1` / `DO_NOT_TRACK=1` 是别名 | 子进程策略生成主开关覆盖；生产 launch 目标仍关闭，不能称为当前 CLI 已停止发送。 |
| T12 | CLI `DISABLE_ERROR_REPORTING=1` 关闭独立错误追踪条件 | 子进程策略已覆盖；生产 launch/runtime 未验。 |
| T13 | CLI `DISABLE_GROWTHBOOK=1` 独立关闭 GrowthBook，避免自定义 `ANTHROPIC_BASE_URL` host 明文随评估请求上报 | 子进程策略已覆盖；生产 launch/runtime 未验。 |
| T14 | 不设置 `CLAUDE_CODE_ENABLE_TELEMETRY`，防止显式启用用户自配 OTLP | 子进程策略明确关闭；远程/网关中继另列。 |
| T15 | 将 OTLP logs/metrics/traces exporters 设为 none；prompt、response、tool content/details、managed settings、raw API bodies 内容采集关闭 | 子进程策略已覆盖普通本地 OTLP；运行时配置优先级、远程会话与生产 spawn 未验。 |
| T16 | 不启用 Beta tracing；关闭 detailed/enhanced tracing flag 并移除 `BETA_TRACING_ENDPOINT` | 子进程策略已覆盖；未用真实 CLI 验证。 |
| T17 | `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS=1` 或 `includeGitInstructions:false`，减少用户名/近期提交进入提示词 | 子进程策略已覆盖前一种；正常模型提示词中的其他上下文仍不归此开关控制。 |
| T18 | 如果实际使用 Bedrock/Vertex/其他支持 provider，应如实设对应 `CLAUDE_CODE_USE_*`；不能伪设第三方类别来关遥测 | Guard 保留用户实际环境，未伪造 provider 标志。 |
| T19 | 清理会出现在 trusted-device/Cowork `display_name` 的个人姓名或公司主机名 | Guard 不自动改系统主机名；按目标进程的 payload 当前值未读取，仍是残余检查项。 |
| T20 | 不从已登录 Desktop 内启动 Code/Cowork，降低跨端 session/account 关联 | Guard 把 CLI/MCP 作为独立目标设计；当前目标未启用，关联路径未运行验收。 |
| T21 | 需要降低 Desktop/CLI 同出口时间关联时可按进程分开出口或不同 ASN；这是隐私选项 | 和“所有 Claude 目标固定同一个 ISP 出口”可能冲突，Guard 仅保留单出口/分出口设计选项，未启用任一生产模式。 |
| T22 | 可手动重置 Desktop install ID、CLI `userID`/`machineID`；这不是遥测开关 | Guard 不自动重置；只有明确的用户数据迁移需求才设计独立、可回滚流程。 |
| T23 | 可按进程或精确域/路径限制部分事件、错误、更新通道；避免全局拦截业务共用域 | Guard 的目标规则仍未登记。路径级 HTTPS 匹配需要受控应用层能力，DNS/SNI 不能准确代替。 |
| T24 | 可选缩减自配 OTLP resource 的 `session.id`、`account_uuid` 和内容字段 | 本地策略关闭 exporter/内容；自配外部 collector 和运行时动态覆盖仍需证明。 |
| T25 | 不把本地导出 Cowork Diagnostic Bundle 当作无外发；导出动作仍会触发事件，并应避免附带敏感路径/文件 | Guard 不读取/修改诊断包；其提示文本不得声称本地导出等于离线。 |
| T26 | Desktop 登出、单独 data directory、轮换 `ant-did` 可降低部分账号/安装关联，但各自不等于关闭遥测 | Guard 不自动登出、换 ID 或迁移私有目录；这些是独立、可逆性不同的用户操作。 |
| T27 | Desktop 内启动 Code/Cowork 的账号与 session 关联不会因关闭 CLI telemetry 消失 | Guard 设计独立目标启动；当前 Claude Desktop host spawn 与 browser login handoff 未纳入已验收链。 |
| T28 | Desktop `otlpEndpoint` 会让自身 OTLP 导出，并可向托管 CLI 注入 `CLAUDE_CODE_ENABLE_TELEMETRY=1`、OTLP exporters/endpoint/headers | Guard 仅读取存在性，未核验并阻断宿主注入；不能把 CLI 本地补丁称作压过 Desktop host policy。 |

### Desktop 与 CLI 出站通道清单

此表把 audit 列出的每条通道单独与 Guard 对照。Desktop 端点按 macOS 2.9939.2，CLI 端点按 darwin-arm64 2.1.283；动态开关/版本/托管策略可能改变运行状态。

| 端 | 通道 / 目的地 | 来源中的切断点 | Guard 状态 |
| --- | --- | --- | --- |
| Desktop | Sentry：`o1158394.ingest.us.sentry.io` | `disableEssentialTelemetry`、Desktop 自身进程 `CI=1`、或精确网络规则 | 只读遥测配置；未写 MDM/进程环境/规则。 |
| Desktop | 一方事件：`claude.ai/api/event_logging/v2/batch`；renderer 中还可能使用 `/api/v2/rum` | `disableNonessentialTelemetry`；path-level 规则；域名级拒绝会误伤共用业务 | 未写设置或网络规则；运行时发送未知。 |
| Desktop | 更新：`api.anthropic.com/api/desktop/.../update` 或 `releases.claude.com`；安装 ID 在 URL | 单独 `disableAutoUpdates` 或 Desktop 进程规则 | 只关闭 Guard fork 自身 updater；Claude Desktop 未改。 |
| Desktop | 模型目录、VM bundle、CLI 二进制：`downloads.claude.ai` | 单独路由/拒绝会使模型目录或资源更新失效 | 未设规则；功能损失须显式呈现。 |
| Desktop | 企业 OTLP：管理员设置的 collector `/v1/logs`；`otlpEndpoint` 也可向 child CLI 注入 OTLP | endpoint 留空或 `otlpDesktopLogLevel=off`；外部 collector 可动态变化 | 只读 endpoint presence；有效版本/托管来源未知，没覆盖 remote host spawn。 |
| Desktop | 可选 Segment `a-api.anthropic.com` / `a-cdn.anthropic.com`、Datadog RUM `browser-intake-*.datadoghq.com` | `disableNonessentialTelemetry`/`disableEssentialTelemetry` 分别覆盖；具体 renderer 端点按进程审查 | 未改托管开关或网络规则；动态 gate 未运行复验。 |
| Desktop | connector favicon、Artifact iframe（默认 `www.claudeusercontent.com`）、MCP Apps `*.claudemcpcontent.com`、dictation 动态 host | `disableNonessentialServices` 涵盖 favicon/artifact/MCP iframe；dictation 无该开关 | 未关功能性请求；须分别评估功能影响，不能称所有可选外发都被关闭。 |
| Desktop | 3p model-catalog：`downloads.claude.ai/model-catalog/v1/catalog.json`，5–15 分钟轮询、credentials omit、无稳定标识符 | 不由 telemetry keys 关闭；需独立功能/进程网络规则 | 未设规则；该轮询本身仍是外发请求，即使没有安装/账号标识。 |
| CLI | A 一方事件：`api.anthropic.com/api/event_logging/v2/batch` | `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 等 aliases | 补丁已实现于 child policy，生产受管 spawn 尚未启用。 |
| CLI | B Datadog logs：`http-intake.logs.us5.datadoghq.com/api/v2/logs` | master nonessential 开关；远端 gate 默认关不等于永久关闭 | 同上；没有当前进程证据。 |
| CLI | C Datadog errors：`browser-intake-us5-datadoghq.com/api/v2/logs` | `DISABLE_ERROR_REPORTING=1` 或 master 开关 | 同上；自建 `ANTHROPIC_BASE_URL` 本身不关闭所有其他通道。 |
| CLI | D 用户自配 OTLP：环境中指定的 logs/metrics/traces endpoint | 不启用 `CLAUDE_CODE_ENABLE_TELEMETRY`，三个 exporter 设为 `none`，内容键为 false | 子进程策略实现；Desktop host-managed OTLP 注入与远程 relay 未验。 |
| CLI | E 内部指标：`api.anthropic.com/api/claude_code/metrics` | master 开关；还受账户/组织和远端 gate 影响 | 子进程策略实现；不据远端当前默认值宣称永久关闭。 |
| CLI | F1 Beta tracing：`${BETA_TRACING_ENDPOINT}/v1/traces`、`/v1/logs` | 不设 endpoint；关 detailed/enhanced tracing flags | 子进程策略移除 endpoint 并关 flags；无 CLI runtime 证据。 |
| CLI | F2 远程/gateway OTLP relay：`SESSION_INGRESS_URL` 或 gateway `ANTHROPIC_BASE_URL` 的 `/v1/{signal}` | 依赖 host/session/gateway 环境，非普通 master 开关可证明覆盖 | 只做 presence-only 诊断；条件不足为 unknown，不删 host 的合法会话环境。 |
| CLI | G GrowthBook：`api.anthropic.com/api/eval/...`、SSE `/sub/<key>` | `DISABLE_GROWTHBOOK=1` 或 master 开关 | 子进程策略实现；当前是否发送未运行验证。 |
| CLI | H Sentry、I Statsig | 审计版没有 CLI 的 Sentry/Statsig SDK/出口 | 不添加这两类规则；不把 Desktop Sentry 套给 CLI。 |
| Desktop/CLI | 正常推理请求、OAuth/设备注册等产品功能端点 | telemetry 开关不关闭；须依赖所选代理/进程路由或产品自身数据策略 | payload 不由 Guard 过滤；当前只计划固定网络路径，亦未实测。 |

### 审计确认的“仍会发出”项

| ID | 未被上述遥测开关关闭的流量／关联面 | Guard 状态 |
| --- | --- | --- |
| R01 | 正常模型请求仍到推理端点；CLI 请求可带 device/account/session 标识、cwd/home 等上下文 | Guard 不做模型 payload 改写；只计划限制其网络路径。不得宣称“遥测关闭即匿名”。 |
| R02 | Desktop/CLI 设备/账号标识与请求元数据可稳定关联；自定义 provider host 可能进入 GrowthBook | 本轮加了本机 HMAC 索引与子进程增长实验开关；远端行为未运行验收。 |
| R03 | 远程/gateway session 的 OTLP relay 是与常规 CLI 遥测不同的通道 | 诊断仅在输入信息足够时报告 open/off/unknown；生产会话未测试。 |
| R04 | 第一方部署的 `CoworkSessionDeletionEvent` 走独立通道，不受 `disableNonessentialTelemetry` 关闭；适用范围需按部署模式读回 | 当前部署模式固定 unknown；没有精确目标规则或当前版本运行证据。 |
| R05 | 账户注册、设备认证、登录与模型业务请求不是 telemetry；关闭遥测不关闭它们 | Guard 不改认证内容；受管浏览器登录 handoff 未完成。 |
| R06 | 版本差异、企业托管策略、远程下发与服务端 feature gate 会改变开关效果 | Guard 版本与配置读回采用 unknown；当前版本审计未完成。 |
| R07 | 同一 IP/时间线、Desktop 内拉起 CLI 等行为可产生跨端关联；分开出口会影响用户选定的固定出口策略 | 未做用户流量测试；属于需明确选择的隐私模式，不是默认强制项。 |

来源：固定快照内 [README §5](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/README.md)、[Desktop audit](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/telemetry/desktop.md)、[CLI audit](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/telemetry/cli.md)、[cross-client link audit](../../evidence/protection-union-20261014/sources/claude-telemetry-audit/telemetry/linked.md)。

## Guard 自身具备的控制与剩余缺口

G 项是这轮改动后的候选能力，不是原有受保护安装的事实。当前已安装 Guard 与网络配置未被改写。

| ID | Guard 控制 | 当前结论 |
| --- | --- | --- |
| G01 | 统一状态 `unavailable/locked/checking/active/recovery`；`status/inspect` 只读，不能授予网络权限 | UI、Rust 协调器与 fixture 覆盖；无平台 backend 时 start 失败关闭。 |
| G02 | `start → validate → prepare → permit → launch`，锁定先关闭入口再停止；回收不自动启动/解锁 | 协议和纯逻辑有测试；平台 permit、崩溃和现存连接需原生验收。 |
| G03 | 许可短时效、过期关闭、操作代次、进程/owner identity 与退出清理读回 | 规则/fixture 覆盖；系统时序未实测。 |
| G04 | 所有目标启动入口（UI/IPC/默认浏览器/外部 launcher 等）不得绕过 Guard | 禁用外部 Browser 直启并覆盖源码路由；真实安装注册和快捷入口待验。 |
| G05 | Guard UI 不把代理变量、单次探针、源码存在、用户授权之外的日志文字当成执行证明 | snapshot 分离 observed IP 和 enforcement；仅 fixture 验证。 |
| G06 | 身份变化与 Browser workspace 同事务；独立 Cookie profile；失败保留 pending/recovery；账号 UUID 用本机 HMAC 索引 | 接入并通过 23 项身份及 workspace fixture；没有真实账号操作。 |
| G07 | CLI 子进程使用受限环境，不继承宿主开发秘密；应用 audit 的非必要流量、OTLP、Beta tracing、内容与 gitStatus 控制 | Rust policy 和启动候选具备；补丁未连接生产 Mac/Windows executor，也不会影响用户独立启动的 Desktop/CLI。 |
| G08 | Desktop telemetry 只读核对版本、部署模式、受管开关与 OTLP presence | 当前 inspect 无条件传 DesktopDeployment/CliLaunchOrigin Unknown，故 Desktop/CLI 控制渠道全 unknown，仅模型请求 open；Windows Desktop/CLI 版本读取路径未接好。 |
| G09 | Mac LuLu backend 按目标准备许可；额外的 child Seatbelt 候选限制至本地 Guard gate、拒绝入站/绑定/未授权 FD | Guard Mac start adapter 缺生产 manifest；编译的 `ManagedLaunchCandidate` 无生产调用点；`setsid()` 后代不能确认退出，目标 unavailable。 |
| G10 | Windows WFP/SCM 读回；broker 专用主令牌；挂起创建、Job 归组、核验后放行 | WFP 读回候选可用；Windows `Start` 明确未接 permit/launch path；专用账户/service/broker/WFP 写入和 Windows API 目标验收未做，目标 unavailable。 |
| G11 | Network Skill 静态预检、两阶段 SSH pin、防直接脚本绕过；DoH 按路由走 HTTPS | 本轮源代码与 15 项离线测试通过；没有 SSH/VPS/TUN 实测。 |
| G12 | Android 排除；不把 WSL2/Docker 写成已支持 | Android 本轮排除；WSL2/Docker 仍无可继承的已验收源能力。 |
| G13 | Linux native Guard backend：目标进程隔离、TUN/route 管理、deny baseline、过期关闭及生命周期读回 | 当前 Guard contract 没有 Linux backend；本轮按 Fox 最新决定暂停，不列入当前 Mac 工作或 Windows 移交。 |

## 冲突裁决与补齐顺序

这些差异不能通过把三方配置叠起来自动解决：

1. CCBaga 的全机 TUN 和 Guard 的 Claude 目标隔离不是同一范围。默认把 Codex/Obsidian 等也送进 TUN 会改变用户流量边界；接入前须确定受管进程列表与全局路由例外。
2. CCBaga 的国内域名/bootstrap DNS 直连，与“所有目标流量固定住宅出口”冲突；每条例外要有明确目的、范围与实际 DNS/路由证据。
3. telemetry audit 的分出口/不同 ASN 是跨端关联最小化建议，与单出口固定 IP 目标冲突；保留成可选模式，不能同时宣称两者默认满足。
4. 关闭遥测仍会发模型请求、设备注册、登录及一部分远程/网关通道；Guard 需要做受管路径控制，不能把环境变量开关称作全出站防护。
5. 整域拒绝 `api.anthropic.com` 会误伤登录/推理。只改精确事件路径需明确的应用层实现；本轮没有 TLS 解密方案，也没有在系统规则里伪造 URL 路径控制。
6. 关自动更新、Artifact/MCP Apps、dictation 等有功能代价；须各自显示并由用户选择，不应作为无声默认。
7. 优先顺序：先完成当前版本遥测来源的最后 spawn/readback 接线；再把 Mac/Windows 系统执行器与 sealed manifest/broker 接通；随后按目标逐项验固定出口、IPv4/IPv6/TCP/UDP/DNS/Browser/WebRTC、关闭/崩溃/睡眠/重启和恢复。实机验收前目标继续 unavailable。

## 证据边界

全量 Rust fixture `126 passed, 1 ignored, 1 filtered`；滤掉的是会绑定本机 TCP 端口的浏览器备援测试。另有前端双语 9 项、网络 Skill 15 项、Mac managed-launch fixture、Windows WFP 17 项及 Windows launch fixture 通过。Preview `~/Applications/Guard Preview.app`（Bundle ID `local.fox.guard.preview`）已并排安装、签名核验；未启动、未登记、无 LuLu manifest，也没运行实际 Claude/Browsers、网络探针或 VPS。源构建、fixture、安装 Preview 都不证明任何目标网络执行已生效。
