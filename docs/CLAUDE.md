# docs/
> L2 | 父级: ../CLAUDE.md
README 与 usage.md 使用这些公开资料；不含本机账户、Apple 私钥或用户运行数据。
brand-logos.svg: 两个品牌图并肩的圆角裁切布局，内嵌压缩副本以适配 GitHub；源图与应用图标不变。
architecture.svg: 极客像素风的真实架构连线图，Rust 连接平台 API/浏览器回环，网络入口指向用户在 AI 中独立安装运行的 Skill，再连接 VPS 与家宽出口；应用不执行 SSH。
readme-hero.png: 新生成并压缩的极客像素封面，双终端、清理与浏览器围绕本地芯片；概念插画，不是实测截图。
windows.md: SQLite 身份暂存/用户保留/恢复与当前用户单 NSIS 双程序、默认保留资料与显式删除资料选项、受保护默认关联、真实时区/语言核验、CLI 来源管理/原生安装器预检失败保留旧程序与 Skill 的平台边界；桌面权限和真实 TUN 单独验证。
linux.md: 本地身份保险库及 Linux/Arch x86_64 构建依赖、原生 pacman 包与三种 Tauri 包格式、源码安装、本地验证及语言/钥匙串/定位/旧发行版兼容的实测边界。
usage.md: 英文旅居人员本人身份管理用途声明、功能速查、CLI/删除边界与账号受限步骤和官方入口；不写死版本、政策生效日期或封禁统计。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md

Guard integration: guard-contract.md is the approved business boundary; guard-acceptance.json is the shared Mac/Windows acceptance inventory. No fixture result is native enforcement evidence.

network-protection-acceptance.md: CCBaga Network Skill 的源码事实、离线测试范围与 VPS/客户端/TUN/DNS/WebRTC/IPv6 实机验收步骤；离线结果不得表述为已部署或网络已验证。

guard-executor-integration.md: Mac 静态执行器、Windows WFP 基础、运行节拍、Gate pending 关闭屏障、controller 崩溃后监督缺口/方案及未验收边界。
windows-offline-handoff.md: Windows 源码接手、隔离依赖与只执行指定离线检查的步骤。
windows-managed-launch.md: Windows专用账户封存目标、挂起到Job启动、可信pipe、子进程隐私环境和退出读回候选；未接生产且需Windows实机验收。

protection-union.md: 非Android保护并集实施范围、分工、来源与尚待实机证明的缺项。
protection-capability-inventory.md: CCBaga、telemetry audit 原子保护能力清单、逐项 Guard 状态、冲突与补齐顺序；来源版本和离线/实机证据分开。
privacy-controls.md: Desktop/CLI分通道策略、候选版本及接入/运行时验证边界。
managed-launch.md: Mac Code/MCP/浏览器受管启动候选、Seatbelt/进程组/隐私环境与尚未解决的后代及登录交接边界；生产目标保持不可用。
