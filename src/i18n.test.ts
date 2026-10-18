/**
 * [INPUT]: 中英文 YAML、共享翻译入口与 TypeScript 源码目录。
 * [OUTPUT]: 双语键/插槽一致性、Guard 运行前提/验收与许可续期文案、原生结果/清理失败、有界清点证据及同次读回翻译和语言切换回归。
 * [POS]: 本地化的离线验证；不启动图形界面，不修改系统语言或用户设置。
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import {test,expect} from 'bun:test';
import {readFileSync,readdirSync} from 'node:fs';
import {parse} from 'yaml';
import ts from 'typescript';
import {translate,setLocale} from './i18n';
import {canStartGuard, initialGuardSnapshot, isGuardSnapshot, runtimePrerequisiteLabelKey} from './guard-model';
const zh:Record<string,string>=parse(readFileSync(new URL('./locales/zh.yaml',import.meta.url),'utf8'));
const en:Record<string,string>=parse(readFileSync(new URL('./locales/en.yaml',import.meta.url),'utf8'));
const slots=(value:string)=>[...value.matchAll(/\{(\w+)\}/g)].map(match=>match[1]).sort();
test('unintegrated targets show their own blocker instead of a shared cleanup error',()=>{
  const keys=[
    'CCBaga Browser protected launch is not connected.',
    'Claude Code CLI integration is deferred; candidate code is retained.',
    'MCP integration is deferred; child-process protection is not verified.',
  ];
  const reasons=keys.map(key=>translate(key,{},'zh'));
  expect(new Set(reasons).size).toBe(3);
  expect(reasons[0]).toContain('内置浏览器');
  expect(reasons[1]).toContain('暂缓接入');
  expect(reasons[2]).toContain('暂缓接入');
  expect(translate('Native lock did not confirm workload cleanup.',{},'zh')).toContain('尚未确认受保护进程已清理');
});
test('双语目录完整且命名插槽一致',()=>{
  expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort());
  for(const key of Object.keys(zh)){
    expect(en[key].length).toBeGreaterThan(0);
    expect(slots(en[key])).toEqual(slots(zh[key]));
    // 应用真实路径与名称保留，其他英文文案不得混入中文。
    expect(/[\u3400-\u9fff]/.test(en[key].replaceAll('CCBaga-B.app',''))).toBe(false);
  }
});
test('每个界面源文案与辅助名称都在 YAML 中',()=>{
  for(const name of readdirSync(new URL('.',import.meta.url)).filter(name=>name.endsWith('.tsx'))){
    const source=readFileSync(new URL(name,import.meta.url),'utf8');
    const file=ts.createSourceFile(name,source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
    function walk(node:ts.Node){
      if(ts.isCallExpression(node)&&node.expression.getText(file)==='t'&&ts.isStringLiteral(node.arguments[0]))expect(Object.hasOwn(zh,node.arguments[0].text)).toBe(true);
      if(ts.isJsxText(node))expect(/[\u3400-\u9fff]/.test(node.text)).toBe(false);
      ts.forEachChild(node,walk);
    }
    walk(file);
  }
});
test('原生错误、参数和原始路径可切换语言，未知消息原样保留',()=>{
  setLocale('en');
  expect(translate('已结束 4 个 Claude 进程，可以清理。')).toBe('Stopped 4 Claude processes. Ready to clean.');
  expect(translate('配置残留 · ~/.claude/settings.json')).toBe('Configuration · ~/.claude/settings.json');
  expect(translate('Error: 清理快照已过期，请重新扫描。')).toBe('Error: Scan snapshot expired. Run another scan.');
  expect(translate('钥匙串删除失败：已取消系统授权；余下凭据未处理。（OSStatus -128）')).toBe('Keychain deletion failed: System authorization cancelled. Remaining credentials left unchanged. (OSStatus -128)');
  expect(translate('本机：America/New_York；浏览器：待测；出口：待测')).toBe('Computer: America/New_York; browser: Not checked; exit: Not checked');
  expect(translate('已处理 2 项；部分完成，请检查失败记录。')).toBe('Processed 2 items; partially complete. Check the error log.');
  expect(translate('出口检测未完成（ipwho.is：HTTP 429；ipapi.co：网络连接失败）。请检查 TUN/代理连接后重试。')).toBe('Exit check failed (ipwho.is: HTTP 429; ipapi.co: Network connection failed). Check your TUN/proxy connection and retry.');
  expect(translate('未知错误 0xABC')).toBe('未知错误 0xABC');
  expect(translate('__proto__')).toBe('__proto__');
  const raw='已发现 12 个可选项目。';
  expect(translate(raw)).toBe('Found 12 selectable items.');
  setLocale('zh');expect(translate(raw)).toBe(raw);
  setLocale('fr');expect(translate('网络环境')).toBe('网络环境');
  setLocale('en');expect(translate('时区已核验。{v0}',{v0:'首选语言与地区格式已保存，部分应用需重启或注销。'})).toBe('Time zone verified. Preferred language and region saved. Some apps require restarting or signing out.');
  setLocale('zh');
});
test('Guard separates current runtime prerequisites from artifact acceptance and explains lease renewal',()=>{
  const runtime='当前运行前提已核对';
  const acceptance='此界面未收到与当前工件绑定的平台验收记录。';
  const lease='三秒许可在 Rust 续期源停止后到期；React 界面卡住不一定会停止 Rust 续期。';
  expect(translate(runtime,{},'zh')).toBe(runtime);
  expect(translate(runtime,{},'en')).toBe('Current runtime prerequisites checked.');
  const unverifiedRuntime = runtimePrerequisiteLabelKey(false);
  expect(unverifiedRuntime).toBe('当前运行前提尚未验证');
  expect(translate(unverifiedRuntime,{},'zh')).toBe('当前运行前提尚未验证');
  expect(translate(unverifiedRuntime,{},'en')).toBe('Current runtime prerequisites not verified.');
  const activeUnverified = 'Guard 报告正在运行，但当前原生运行前提尚未验证。';
  expect(translate(activeUnverified,{},'zh')).toBe(activeUnverified);
  expect(translate(activeUnverified,{},'en')).toBe('Guard reports active, but the current native runtime prerequisites have not been verified.');
  expect(translate(acceptance,{},'zh')).toBe(acceptance);
  expect(translate(acceptance,{},'en')).toBe('This UI has not received an artifact-bound platform acceptance record.');
  expect(translate(lease,{},'zh')).toBe(lease);
  expect(translate(lease,{},'en')).toBe('The 3-second permit expires when the Rust renewal source stops; a frozen React UI does not necessarily stop Rust renewals.');
});
test('Guard HTTPS probe diagnostics are translated at the display boundary',()=>{
  const prepare='Preparation failed: observation_https_probe_ipinfo_status_28_timeout_0_phase_tls';
  const start='Start verification failed: observation_https_probe_cloudflare_status_28_timeout_0_phase_proxy_connect';
  const full='Full verification failed: observation_https_probe_cloudflare_status_35_timeout_1_phase_response';
  expect(translate(prepare,{},'zh')).toBe('出口核验失败：ipinfo.io 的 HTTPS 探测未能完成（上游建连／TLS）；尚未验证出口 IP。');
  expect(translate(prepare,{},'en')).toBe('Exit verification failed: the HTTPS probe to ipinfo.io did not complete during upstream connection / TLS; the exit IP is unverified.');
  expect(translate(start,{},'zh')).toBe('启动前出口核验失败：Cloudflare 的 HTTPS 探测未能完成（代理 CONNECT）；尚未验证出口 IP。');
  expect(translate(start,{},'en')).toBe('Pre-start exit verification failed: the HTTPS probe to Cloudflare did not complete during proxy CONNECT; the exit IP is unverified.');
  expect(translate(full,{},'zh')).toBe('运行中出口复核失败：Cloudflare 的 HTTPS 探测未能完成（服务器响应）；尚未验证出口 IP。');
  expect(translate(full,{},'en')).toBe('In-session exit recheck failed: the HTTPS probe to Cloudflare did not complete during server response; the exit IP is unverified.');
});

test('Guard keeps timeout source, curl code and elapsed time instead of collapsing TLS failures',()=>{
  const cases = [
    [7, 'connection_error', '无法建立连接'],
    [28, 'curl_timeout', 'curl 连接或请求超时'],
    [35, 'tls_error', 'TLS 协商错误'],
    [60, 'certificate_error', '证书校验失败'],
    [9, 'process_timeout', '外层探测进程超时'],
  ] as const;
  for (const [status,cause,label] of cases) {
    const raw=`Preparation failed: observation_https_probe_ipinfo_status_${status}_cause_${cause}_phase_tls_elapsed_ms_5002`;
    expect(translate(raw,{},'zh')).toBe(`出口核验失败：ipinfo.io，${label}；阶段：上游建连／TLS（curl ${status}，耗时 5002 ms）。`);
    expect(translate(raw,{},'en')).toContain(`curl ${status}, elapsed 5002 ms`);
  }
  for (const prefix of ['Start verification failed','Full verification failed']) {
    const raw=`${prefix}: observation_https_probe_cloudflare_status_28_cause_curl_timeout_phase_tls_elapsed_ms_8000`;
    expect(translate(raw,{},'zh')).toContain('Cloudflare，curl 连接或请求超时');
    expect(translate(raw,{},'en')).toContain('curl 28, elapsed 8000 ms');
  }
});

test('port observation diagnostics stay diagnostic, localized, and safe for unknown values',()=>{
  const diagnostic='端口观察诊断';
  const caution='只用于诊断，不代表流量已受保护、许可有效或平台验收通过。';
  const legacy='旧格式采集器报告监听缺失';
  const noListener='读取器确认此端口不存在';
  const failure='无法安全读取端口观察文件';
  const allDisplayLabels=[
    '观察文件','观察文件不可读取','观察文件内容无效','观察文件可读取',
    '观察数据结构','观察数据结构无效','观察数据结构有效','采集器状态',
    '采集器报告正常','采集器读取监听信息失败','采集器无法启动监听读取工具','采集器输出超出大小限制',
    '采集器输出格式无效','两次端口采样结果不一致','两次采样间监听进程身份发生变化',
    '无法核对监听进程身份','端口采样耗时过长','采集器时钟无法读取','采集器启动会话无法读取',
    '旧格式采集器读取监听信息失败',
    '上游端口（7896）','Guard 入口（17897）','读取器确认此端口不存在','端口记录无效','采集器报告端口存在',
    '入口身份核对','入口身份尚未核对','与已报告入口身份一致','与已报告入口身份不一致',
    '启动会话核对','启动会话记录无效','与当前启动会话一致','与当前启动会话不一致',
    '墙钟新鲜度','单调时钟新鲜度','时间戳无效','新鲜','已过期','时间在未来','端口观察时间',
    '观察失败原因','未报告失败','无法核对端口观察文件信息','读取端口观察文件失败',
    '端口观察文件超出大小限制','读取期间端口观察文件发生变化','端口观察服务不可用',
    '观察数据结构无效','系统启动会话不一致','系统启动会话无法核对','单调时钟无法核对',
    '端口观察记录已过期','端口监听记录无效','端口观察记录未报告监听器',
    '入口进程身份与记录不一致','无法核对入口进程身份',
  ];
  for(const key of [diagnostic,caution,legacy,noListener,failure,'未知',...allDisplayLabels]) {
    expect(Object.hasOwn(zh,key)).toBe(true);
    expect(Object.hasOwn(en,key)).toBe(true);
  }
  expect(translate(caution,{},'en')).toBe('For diagnosis only. This does not mean traffic is protected, a permit is valid, or platform acceptance passed.');
  expect(translate(legacy,{},'en')).toBe('Legacy producer reports a missing listener');
  expect(translate(noListener,{},'en')).toBe('Reader confirmed no listener on this port');
  expect(translate(failure,{},'en')).toBe('Could not safely read the port observation file');
  expect(translate('两次端口采样结果不一致',{},'en')).toBe('The two port samples did not match.');
  expect(translate('两次采样间监听进程身份发生变化',{},'en')).toBe('A listener process identity changed between samples.');
  expect(translate('端口采样耗时过长',{},'en')).toBe('The port sample took too long.');
  expect(translate('未知',{},'en')).toBe('Unknown');
  expect(translate('未知（查询不可用）',{},'en')).toBe('Unknown (query unavailable)');
  expect(translate('未知（无法核对）',{},'en')).toBe('Unknown (not checked)');
  // Raw native values are sanitized by the model before display; this test checks only localized copy.
});


test('bounded multi-site history keeps terminal budget and each site in both languages',()=>{
  const raw='Full verification failed: observation_inspection_budget_exceeded_elapsed_ms_25000\nhttps_probe_ipinfo_status_0_cause_ok_phase_response_elapsed_ms_4000\nhttps_probe_cloudflare_status_28_cause_curl_timeout_phase_tls_elapsed_ms_3000';
  const zh=translate(raw,{},'zh');
  expect(zh).toContain('核验超出 25 秒总预算（耗时 25000 ms）');
  expect(zh).toContain('ipinfo.io，出口 IP 一致');
  expect(zh).toContain('Cloudflare，curl 连接或请求超时');
  expect(zh.split('\n')).toHaveLength(3);
  const en=translate(raw,{},'en');
  expect(en).toContain('25-second inspection budget was exceeded');
  expect(en).toContain('ipinfo.io, exit IP matched');
  expect(en).toContain('Cloudflare, curl connection or transfer timed out');
  expect(en.split('\n')).toHaveLength(3);
  expect(translate('Start verification failed: observation_https_probe_ipinfo_status_0_cause_exit_mismatch_phase_response_elapsed_ms_21',{},'zh')).toContain('出口 IP 与要求不符');
  expect(translate('Preparation failed: observation_inspection_cancelled',{},'en')).toContain('Inspection cancelled');
});


test('native cleanup reasons and same-call readbacks remain visible without enabling Start',()=>{
  const cases = [
    ['cleanup_pending_prepare_0_open_0_launch_1', '操作尚未完成', 'Operations remain pending'],
    ['cleanup_signature_mismatch_pid_40101', '进程签名复核不匹配', 'Process signature recheck did not match'],
    ['cleanup_process_changed_pid_40101', '进程身份在复核期间变化', 'Process identity changed'],
    ['cleanup_process_inspection_incomplete', '进程清点不完整', 'Process inspection is incomplete'],
    ['cleanup_signal_failed_pid_40101_code_70', '按固定身份发送终止信号失败', 'Identity-pinned termination signal failed'],
    ['cleanup_process_still_running', '最终清点仍有受保护进程', 'final inventory'],
    ['cleanup_supervisor_launch_in_flight', '启动回调未结束', 'in-flight launch callback'],
    ['cleanup_confirmation_rejected', '最终清理确认被拒绝', 'Final cleanup confirmation was rejected'],
  ];
  for(const [key, chinese, english] of cases){
    const reason='Native lock did not confirm workload cleanup.\nCleanup diagnostic: '+key+'; confirmed=0, bound=1, open=0, pairs=0, owned=1, pending=0.';
    const snapshot={...initialGuardSnapshot(), state:'recovery' as const, reason,
      targets:[{id:'claude' as const,label:'Claude',available:true,reason:null}],
      events:[{sequence:1,level:'error' as const,message:reason,recordedAtUnixMs:1792075450000}]};
    expect(isGuardSnapshot(snapshot)).toBe(true);
    expect(canStartGuard(snapshot,'claude')).toBe(false);
    expect(translate(reason,{},'zh')).toContain(chinese);
    expect(translate(reason,{},'en')).toContain(english);
    expect(translate(reason,{},'zh')).toContain('确认=0');
    expect(translate(reason,{},'en')).toContain('confirmed=0');
  }
  expect(translate('Cleanup diagnostic unavailable: cleanup_bridge_completion_failed.',{},'zh')).toContain('清理桥接调用未完成');
});


test.skipIf(!process.env.GUARD_INVENTORY_SNAPSHOT_FIXTURE)('native inventory evidence survives actual Rust snapshot/events and bilingual display',()=>{
  const snapshots: unknown[]=JSON.parse(readFileSync(process.env.GUARD_INVENTORY_SNAPSHOT_FIXTURE!,'utf8'));
  expect(snapshots).toHaveLength(16);
  const steps=new Set<string>();
  for(const raw of snapshots){
    expect(isGuardSnapshot(raw)).toBe(true);
    if(!isGuardSnapshot(raw))throw new Error('Invalid native fixture');
    expect(raw.state).toBe('recovery');
    expect(canStartGuard(raw,'claude')).toBe(false);
    const reason=raw.reason!;
    expect(reason.length).toBeLessThanOrEqual(1024);
    expect(raw.events.at(-1)?.message).toBe(reason);
    expect(reason).toContain('confirmed=0, bound=1, open=0, pairs=0, owned=1, pending=0.');
    expect(reason).toContain('psBytes=8193, psFlags=1.');
    const step=reason.match(/step=(inv_[a-z_]+),/)![1];steps.add(step);
    const chinese=translate(reason,{},'zh'),english=translate(reason,{},'en');
    expect(chinese).toContain('清点证据：目标=Claude');
    expect(chinese).toContain(zh[step]);expect(english).toContain(en[step]);
    expect(chinese).toContain('ps字节数=8193');expect(english).toContain('psBytes=8193');
    expect(chinese).not.toContain('inv_');expect(english).not.toContain('inv_');
  }
  expect(steps.size).toBe(16);
});
