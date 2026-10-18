# 端口 observer 候选实现迁移说明

当前仓库没有找到已安装 observer 的生产源码。现有信息只有安装位置
`/Library/PrivilegedHelperTools/local.fox.claude-port-observer`，以及曾观察到的
`ok: false, status: missing_listener, listeners: []` 输出。因此不能从该输出判断
7896 或 17897 哪个端口缺失，也不能据此声称已验证旧 producer 的采样语义。

`PortObserverCandidate.swift` 与 `ObserverIdentity.c` 是供离线审阅的替换候选，
不是旧实现的恢复或逐行移植。候选固定执行两次 `lsof -nP -iTCP -sTCP:LISTEN -Fpn`，
只在两次采样中每端口的 PID/端点集合相同，且第二次 lsof 前后的 PID、birth、path 相同并
有效时，才将第二次 lsof 的 listener 身份标成成功。使用采样开始的墙钟和单调时钟作为
时间戳；整次双采样超过 2.5 秒、行事实变化、身份变化或身份不可读都失败关闭，且不把
未确认的端口改写成“缺失”。单次快照使用共同的时间戳和 boot UUID，reader 只接受该
快照层级的代次字段。

候选 `status` 枚举冻结为 `ok`、`spawn_failed`、`lsof_read_failed`、`too_large`、
`malformed_output`、`identity_read_failed`、`identity_changed`、`sample_changed`、
`sampling_too_long`、`clock_failed`、`boot_uuid_failed`。reader 仍接受旧 producer
状态 `missing_listener` 与 `netstat_read_failed`；非 `ok` 状态按
`RootPortObserver.admissionFailure` 映射为 `root_observer_<status>`，其中
`missing_listener` 映射为 `root_observer_missing_listener`。

这份候选源码没有集成到构建、launchd 配置或安装流程，也未被部署或作为特权服务运行。
离线 fixture 注入两次 lsof 字节、时钟和身份读取结果，不会调用 lsof、读取真实 observer 文件、查找真实 PID，或写入
`/Library/PrivilegedHelperTools`、`/private/var/db`。将来如需迁移，应先取得并审阅旧
producer 源码及其独立安装配置，再逐项比较采样、身份校验、权限和原子写入合同；通过该
审阅前，不能把此候选标记为与现行安装等价或已验证。

## Standalone stdout diagnostic CLI (A2/A3)

The diagnostic executable reuses this directory’s `PortObserverCandidate.swift` and `ObserverIdentity.c` directly. No arguments or an unknown mode only print usage; `--stdout-once` and `--stdout-watch` are explicit stdout-only modes. The build script requires a new output directory and refuses to overwrite an existing one. It does not define `PORT_OBSERVER_HELPER_MAIN`, install a service, or invoke `writeCurrentSnapshot`; the existing privileged writer contract is therefore not the CLI default. Watch handles SIGINT/SIGTERM by finishing the current synchronous sample/output attempt and stopping before the next sample. Its 2.5-second status threshold is not a hard cancellation guarantee. This CLI is diagnostic only and is not wired to the installed helper or launchd.
