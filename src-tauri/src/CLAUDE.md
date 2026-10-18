# src/
> L2 | 父级: ../CLAUDE.md
清理在本机执行；网络页只提供固定资源入口，SSH 由应用外 Skill 执行。生产命令提供身份压缩暂存、空身份切换、恢复与独立确认的直接删除；原有批量清理事务只保留测试样本。用户选择保留或随身份暂存，系统设置独立。
identities/ - SQLite 身份目录、用户保留策略、加密压缩暂存、空身份切换、恢复与选择性直接删除；见其 CLAUDE.md。
cleaner_identity.rs: 身份目标与保留策略适配；测试显式断言规范源路径，复用白名单、完整快照与窄 JSON 键操作，不扫描源码。
updater_tests.rs: 官方更新器本机 HTTP 公开向量验证篡改与版本冒用；发布显式传入实际清单/归档，下载核验而不安装。
main.rs: Tauri 生命周期、双语托盘和清理/CLI/浏览器/固定网络入口命令注册；原生 Guard 管理敏感操作与退出，更新/重启插件不注册；CCBaga-B 启动入口由浏览器原生层校验；退出删除 start.url；发布缺少 custom-protocol 时编译失败。
guard.rs: Native Guard 的唯一状态权威、五条 Tauri 命令、带记录时间与失败原因的有界事件快照、generation/cancellation token 与目标级闸门；未接入真实平台执行器时始终 unavailable，拒绝受保护操作，检查不能授权，测试状态不代表宿主防护。
guard_macos.rs: LuLu 原生执行器；finish-lock 保留具体清理原因、单次有界清点证据及同次六项读回，故障锁存不覆盖诊断；原有身份、终止范围与确认条件不变。
guard_windows.rs: Windows x64 固定 WFP 产品 GUID 的只读检查与 SID 绑定持久拒绝事务；构造不触碰 WFP，原生写入仍因专用标准账户、服务、gate 和 launcher 尚未 provision 而 hard-disabled；离线 fake-store 测试不证明 Windows SDK ABI 或数据面生效。
guard_windows_launch.rs: 未接生产的 Windows 专用账户候选；封存目标、挂起启动、Job、可信stdio、子进程隐私环境和退出读回，只有认证broker主令牌路径可供生产接线。
ui_language.rs: 受 zh/en 白名单限制的界面偏好，原子持久化后发布内存状态；共用托盘菜单，独立于电脑与浏览器语言。
browser/: 指纹浏览器、资料与缓存边界、真实浏览器回报及目标地区环境核验；见其 CLAUDE.md。
windows.rs: Win32 剪贴板、当前用户 SID/文件所有权、Win32 直接读取时区/语言、缓存系统版本与用户触发设置；控制台工具隐藏窗口，外部链接；拒绝凭据管理器自动读取和 SSH 操作。
windows_timezones.rs: CLDR 48 固定全量 Windows/IANA 映射与目录别名，无运行时下载或猜测；原始许可证作为 Windows 资源交付。
windows_process.rs: 当前用户 Toolhelp/MSIX 固定 Claude 包族与精确 CLI 参数识别、创建时间和句柄复核、独立资料的正常窗口关闭；原始参数不序列化，超时子进程使用 Job Object；Windows CI 回归实际映射时区写入后还原。
system.rs: 电脑环境只读查询和设置入口保持可用；时区/语言/定位/区域写入要求当前可用 Guard 目标均已核验，并复用 Cleaner 事务锁。
native.rs: 剪贴板、辅助功能设置、进程编号与凭据解锁桥；旧扫描只读凭据属性；身份快照/恢复仅原生可用，默认服务正文不送 UI。
cleaner.rs: 全机/文件夹扫描与快照保护、只读进程状态；Windows 外置 AppData 只允许同一目标白名单且复核规范路径/用户所有权；原生 CLI 识别当前用户官方 versions 下的精确数字版本程序；Claude 进程停止逐轮核验与收敛；CLI、身份与 Guard 业务动作共用可释放事务锁，锁请求可排队等待当前操作释放。
claude_cli.rs: 内嵌脚本的只读状态与 CLI 程序卸载/重装，登录终端加载 nvm 环境，固定动作与原生互斥锁限制修改；真实阶段沿用进度通道，超时结束本次子进程组或 Job Object；Windows 完成时先回收本次子进程树再读取完整协议，成功要求完整回报；临时目录测试清空继承环境并在 zsh 启动后固定样本 PATH，验证版本、卸载、资产保留和失败不报成功，不能探测或卸载真实安装。
cleaner_folder.rs: 用户所选目录内的 Claude 白名单发现；不跟随链接、不扫描目录外、不处理项目权限或凭据。
progress.rs: 有序脱敏阶段事件与有界内存日志；供清理与浏览器共享，只读取事务传入的计数和状态。
cleaner_transaction.rs: 仅 cfg(test) 的历史快照/删除样本回归；不编译进生产身份事务，不注册永久清理命令。
cleaner_targets.rs: Claude 白名单、桌面登录存储子目录（不删整个应用资料目录）、完整目录规模和元数据指纹（无时间/条目截断，读取失败不生成可删除快照）、按 Windows 实际 AppData 的旧组织会话检索；不进入链接目标或项目源码。
cleaner_config.rs: 账号缓存和代理认证配置的窄范围变换；保留其他配置并只返回键名。
cleaner_io.rs: 清理后配置原子写入；Windows 写入前保留原所有者/DACL，临时文件仅保存新内容，失败移除，不保留原配置。
cleaner_tests.rs: 临时白名单/快照/日志验证，覆盖超过 30,000 文件的完整清理与权限失败保护；共享 operation lease 排他与释放；官方原生版本路径、自编译并经启动握手的可丢弃进程与 Node 样本验证身份、终止与其他 Node 保留；Windows 子进程隔离的外置 AppData 验证白名单和身份目标，不复制系统平台二进制，不修改用户数据。
regions.rs: 地区编号到语言、区域格式和代表时区的唯一白名单与目标语言/时区地区匹配；供前端选择与系统/浏览器快捷操作共用，包含目录与本机时区验证。
linux.rs: Linux procfs 当前用户进程、zoneinfo/timedatectl、GNOME 定位偏好、GNOME/KDE 设置入口与 Wayland/X11 剪贴板；LC_MESSAGES/LC_TIME 分别读取会话语言/区域格式，不匹配时先报手动操作再改时区；未知定位为 null，Linux 钥匙串明确不可用；不将系统代理凭据序列化给 WebView。
network_links.rs: 固定供应商与 Skill 导航白名单，编译消费 Skill 的 providers.json 组装原始 URL，WebView 不能指定 URL；无密钥访问或 SSH 执行。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md

guard_macos.rs: 按目标返回未接通／暂缓原因、惰性 Swift ABI、逐调用错误缓冲、独立租期续期与完整复核、异步故障清理；prepare 才初始化，现用环境验收另行进行。

guard_privacy.rs: 子进程级遥测策略与版本/部署模式诊断；不读写配置、不把配置意图升格为运行时执行。
guard_privacy_readback.rs: 固定客户端元数据和系统托管字段只读适配；不输出凭据/端点、不启动应用、不签发许可。
