# Guard 保护能力融合

本轮实施先做 Mac；Windows 保留设计文档，待移交 Windows 主机后修改。Android 排除；CCBaga 的 Linux x86_64 来源能力保留在清单，但按 Fox 最新决定暂不实施。WSL2、Docker 没有可继承的实机保护能力，不能按其他平台结果视作已支持。

## 来源与执行边界

- Guard 当前工作区基于 CCBaga `aff6122719c479effd4d53c7d875bcc3c04edcc8`，保留此前未提交改动。
- CCBaga 对照版本：`a3a663a30add6cb4c3065a3e9ddb470141d181af`。
- telemetry audit：`bf1fa2075050e67cc3db10155c193ff1e08a0569`，源码快照见 `../../evidence/protection-union-20261014/sources/`。
- 审计 Desktop 2.9939.2 / CLI 2.1.283；本机静态观察为 Desktop 2.110.0 / CLI 2.1.296。配置键存在不等于当前版本完整复验通过。
- 代码、类型检查、临时目录测试和系统实测分开记录。未安装的能力保持不可用；身份提交或探针成功不能签发网络许可。
- Mac `Guard Preview.app` 已并排安装到当前用户 Applications 目录，仅供静态界面与 unavailable 状态审阅；未启动、未登记、未写入 manifest。没有安装服务或规则，没有操作账号/资料，没有改 FlClash、LuLu、系统代理或 TUN，也没有做联网/断网测试。正式接管前给出目标规则、系统授权和测试回退步骤。

## 三方能力并集与 Guard 逐项状态

这里的 telemetry audit 是遥测与外发面的静态审计，不是一个网络执行器。它贡献“哪些流量／字段会出去、哪些开关只关遥测”的证据；实际拦截仍要由 Guard 的进程边界、系统网络规则或部署配置完成。状态栏描述当前 Guard 集成候选，不把离线测试算作系统保护通过。

| 能力单元 | 三方提供的能力或证据 | Guard 当前状态与缺口 |
| --- | --- | --- |
| 固定出口、禁止旁路 | Guard 的目标是目标级固定出口、关闭时拒绝启动与许可到期；CCBaga Network Skill 生成经家用 SOCKS 出口的 Mihomo/Xray 配置，受保护 TCP 无 direct fallback；telemetry audit 列出事件、配置拉取、OTLP、更新及模型请求等不同出站面，但不控制路由。 | 会话状态机、gate 与 Mac/Windows 执行候选已接入；真实规则未登记、目标全为 unavailable。还需用真实进程证明出口、拒绝基线、许可到期和已有连接处理。 |
| IPv4/IPv6、TCP/UDP 与 DNS | CCBaga 生成配置显式关闭 IPv6/UDP，并保留国内域名和 bootstrap DNS 直连例外；telemetry audit 提醒遥测开关不改变模型请求。 | 已列为共同验收合同；Mac LuLu 与 Windows WFP 写入和所有协议族的真实仲裁均未验收。DNS、IPv6、UDP 和系统／浏览器解析均无实机证据。 |
| 浏览器出口与泄漏核验 | CCBaga Browser 可按当前浏览器路由测出口、国家/时区/语言/平台与定位状态；出口回显服务会看到请求来源 IP，但不测试 DNS 或 WebRTC。 | 身份到 profile slot/seed 的事务有离线覆盖，Chromium profile 本身不在加密归档中；受管 handoff 未完成，目标 unavailable。需分别验出口、DNS、WebRTC、浏览器 DoH 与关闭 TUN 后恢复。 |
| Claude 身份与浏览器资料隔离 | CCBaga 保存／切换身份、归档和恢复，并将浏览器绑定到独立 profile slot/seed；Chromium profile/Cookie 本身不在加密身份归档里。telemetry audit 揭示请求仍携带设备／账号／会话等字段。 | 独立 workspace、stable seed、账号 HMAC 索引、pending/rollback、活动账号/槽位一致性与启动前核验已有虚构身份 fixture；没有读取或改写真实账号，亦未证明 Claude 服务端数据被隐藏。删除身份时选择保留的浏览器资料会继续留在本机，但绑定身份记录已删除后会 fail-closed，当前没有单独的孤儿资料管理／清理界面。 |
| Desktop／CLI 遥测控制 | telemetry audit 按 Desktop、CLI 列出事件、错误报告、GrowthBook、内部指标、OTLP、Beta tracing 和更新控制；Desktop 的两个遥测开关还分别影响 Datadog RUM、Segment。Claude 模型请求不受这些开关关闭。 | CLI 补丁只在离线候选/测试中，尚未接生产 spawn。只读适配器把 Desktop 部署模式和 CLI 启动来源固定为 unknown，所以当前遥测控制全部 unknown，仅模型请求显示 open；Windows 版本读取也未接好。未写 MDM/GPO。 |
| 账号标识、路径与服务地址外发 | telemetry audit 标出稳定设备标识、请求元数据、工作路径、主机名及自定义 provider host 等外发面；CCBaga 的本地凭据／身份存储保护本地数据边界。 | CLI 候选额外移除模型 prompt 中的 gitStatus 段；Guard 仍不能删改模型请求中的 device/account/session、cwd/home 等字段，也不能据配置推断它们未出站。 |
| SSH 首次信任与服务器部署 | CCBaga Skill 提供 SSH 公钥配对、候选主机指纹与用户核对、私有 pin、服务器预检、Xray/UFW 部署、订阅取回及 TUN 检查；telemetry audit 不提供这些服务端控制。 | Skill 的信任顺序、unknown fail-closed 预检与直跑拒绝已有代码及离线回归；本轮未连接 VPS。真实 host fingerprint、云防火墙、服务规则与回滚均待目标机验收。 |
| 服务器出口与订阅传输 | CCBaga 组合 VPS 与住宅 SOCKS 出口，优先通过 SSH 取回本地配置；公网上的 HTTP 8443 订阅链接是 bearer token，不加密。 | 改为 route-following DoH 并写明风险；无法证明当前服务器实际走住宅出口。生产使用仍需 SSH 拉取，或先决定是否接受明文 HTTP 风险。 |
| 进程生命周期、锁定与恢复 | Guard 定义检查、锁定、启动、撤销、退出确认和恢复；CCBaga 身份切换保留 pending/save/rollback；telemetry audit 不负责进程控制。 | 状态机与 fixtures 通过。Mac 进程组无法证明 `setsid()` 后代退出；Windows 专用账户、broker、WFP service 和真实进程 API 未在 Windows 机验收，所以相关目标保持 unavailable。 |
| 全局设置、更新与普通应用边界 | CCBaga 提供地区／浏览器设置和应用更新；telemetry audit 指出 Desktop 自动更新与遥测是不同开关；Guard 要避免把代理、TUN、共享 Node/Python 或无关应用带入保护范围。 | 现有全局设置和现用 Guard 未改；本 fork 的更新路径关闭。将来需逐项给出变更范围、目标规则、回退和未受保护的普通应用证据。 |
| 平台范围与审计适用性 | CCBaga 有 Mac/Windows 及 Linux x86_64 路径；telemetry audit 的可复验版本是 macOS Desktop 2.9939.2 / CLI 2.1.283，不足以证明其他版本或 Linux/Windows runtime。 | 本轮先做 Mac；Windows 仅维护移交文档，Linux 暂停实现。native Linux backend 未开始；Android 排除，WSL2/Docker 不借用其他平台验收。 |

结论：并集已拆成可检查能力项并实现可离线完成的部分；主要剩余工作是系统层执行器接管、当前版本进程外发证据以及网络／浏览器真实验收，不是再加一个总开关。完整原子能力目录与来源定位见 [`protection-capability-inventory.md`](protection-capability-inventory.md)；逐项验收见 [`network-protection-acceptance.md`](network-protection-acceptance.md)、[`managed-launch.md`](managed-launch.md)、[`windows-managed-launch.md`](windows-managed-launch.md) 与 [`privacy-controls.md`](privacy-controls.md)。

## 分工与接入

| 工作流 | 所有权 | 接入及完成条件 |
| --- | --- | --- |
| 遥测 | `guard_privacy.rs`, `privacy-controls.md` | 单进程环境补丁、版本/部署模式诊断；必须接到最终启动或如实标候选，不冒充已经关断 |
| 身份与浏览器联动 | `identities/`, `identities.tsx`, 身份 fixtures | 同库保存身份到 profile slot/seed 的绑定；Chromium profile/Cookie 不在加密身份归档里；不回写真实身份资料 |
| Windows | `guard_windows.rs`, Windows handoff | SCM/WFP/进程身份实际 API；未经 Windows 实机验收不解除写入与启动闸门 |
| Mac 受管启动 | `native/macos/`, `native/tests/`, `managed-launch.md` | LuLu start adapter 已接 Guard 命令但缺生产 manifest；`ManagedLaunchCandidate` 没有生产调用点，Code/MCP/Browser 仍 unavailable；不限制全机共享 Node/Python |
| 网络部署与验收 | `skills/ccbaga-network/`, network acceptance | 静态配置/秘密边界缺陷修复及离线回归；服务和 DNS/WebRTC 实测另行记录 |
| 总接入与监督 | Browser、Guard host、UI、公共目录和文档 | 保留唯一操作协调、检查所有调用路径、集成构建、独立复审与最终交付 |

## 待关闭的真实缺口

1. 当前版本的 Desktop 和不同 CLI 启动来源，哪些控制实际生效；普通模型请求与远程中继单列剩余外发。
2. Code、MCP、专用登录浏览器及 CCBaga Browser 的实际强制执行，不以代理环境变量或全局共享运行时规则代替。
3. 身份与浏览器切换必须一致；中断、失败回退及身份已提交但浏览器未重开必须分开处理；为用户选择保留的孤儿浏览器资料补独立管理／清理入口。
4. Windows 的受管账户、服务、gate、launcher、既有连接与所有传输族的原生验收。
5. DNS/WebRTC 和真实客户端外发的独立证据；配置存在、单一探针与历史版结果不能代替。
6. 现有前置链路的间歇拨号超时；不得以自动直连、跳过证书检查或接受新出口解决。

## 模式约定

固定单出口与 Desktop/CLI 分出口属于可选择的保护模式。禁用 Artifact/MCP Apps 等非必要服务会影响功能，须独立显示，不作为静默默认。不会自动清除身份、改整机主机名或覆盖现有网络。

## 验证记录

全量 Rust fixture：126 passed、1 ignored、1 filtered；过滤的是会绑定本机 TCP 端口的浏览器备援测试。前端双语 9 项和构建通过，Network Skill 15 项，Mac 启动 fixture 通过，Windows 纯策略 5 项和 WFP 17 项通过。详细离线范围及全部剩余实机验收见 `/Volumes/Bypass_Claude/手册/33-三方保护并集与离线接入-20261014.md`。本页不把这些结果表述为系统执行通过。
