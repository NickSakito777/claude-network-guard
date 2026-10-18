/**
 * [INPUT]: Guard's native Tauri commands, validated snapshots, Cromma controls, and shared YAML strings.
 * [OUTPUT]: Guard home with current runtime prerequisites, distinct artifact acceptance status, probe disclosure, translated probe diagnostics, and timestamped failure events.
 * [POS]: Read-only-by-default home surface; only native command snapshots determine displayed status.
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import { invoke, isTauri } from '@tauri-apps/api/core';
import { Button, Panel, PanelHeader } from 'cromma-ui';
import { useEffect, useRef, useState } from 'react';
import { useI18n } from './i18n';
import { GuardPrivacy } from './guard-privacy';
import { canLockGuard, canRecoverGuard, canStartGuard, initialGuardSnapshot, isGuardSnapshot, isLatestGuardRequest, normalizePortObservation, runtimePrerequisiteLabelKey, type GuardSnapshot, type GuardTargetId, type PortObservationDisplay } from './guard-model';

type Command = 'guard_status' | 'guard_inspect' | 'guard_start' | 'guard_lock' | 'guard_recover';

function stateLabel(snapshot: GuardSnapshot, t: (key: string) => string) {
  if (snapshot.state === 'unavailable') return snapshot.reason === 'NotConfigured' ? t('保护执行器尚未接入') : t('不可用');
  if (snapshot.state === 'locked') return t('已锁定');
  if (snapshot.state === 'checking') return t('检查中');
  if (snapshot.state === 'active') return t('运行中');
  return t('等待恢复');
}

const portObservationLabels = {
  fileState: {
    unreadable: '观察文件不可读取', invalid: '观察文件内容无效', readable: '观察文件可读取', unknown: '未知',
  },
  schemaState: {
    unavailable: '未知（无法核对）', invalid: '观察数据结构无效', valid: '观察数据结构有效', unknown: '未知',
  },
  upstreamState: {
    unavailable: '未知（查询不可用）', missing: '读取器确认此端口不存在', invalid: '端口记录无效', present: '采集器报告端口存在', unknown: '未知',
  },
  ingressState: {
    unavailable: '未知（查询不可用）', missing: '读取器确认此端口不存在', invalid: '端口记录无效', present: '采集器报告端口存在', unknown: '未知',
  },
  ingressOwnerState: {
    unchecked: '入口身份尚未核对', unavailable: '未知（无法核对）', matches: '与已报告入口身份一致', mismatch: '与已报告入口身份不一致', unknown: '未知',
  },
  bootState: {
    unavailable: '未知（无法核对）', invalid: '启动会话记录无效', matches: '与当前启动会话一致', mismatch: '与当前启动会话不一致', unknown: '未知',
  },
  wallFreshness: {
    unavailable: '未知（无法核对）', invalid: '时间戳无效', fresh: '新鲜', stale: '已过期', future: '时间在未来', unknown: '未知',
  },
  monotonicFreshness: {
    unavailable: '未知（无法核对）', invalid: '时间戳无效', fresh: '新鲜', stale: '已过期', future: '时间在未来', unknown: '未知',
  },
} as const;

const producerStatusLabels: Record<PortObservationDisplay['producerStatus'], string> = {
  ok: '采集器报告正常',
  missing_listener: '旧格式采集器报告监听缺失',
  netstat_read_failed: '采集器读取监听信息失败',
  netstat_spawn_failed: '采集器无法启动监听读取工具',
  netstat_too_large: '采集器输出超出大小限制',
  spawn_failed: '采集器无法启动监听读取工具',
  lsof_read_failed: '采集器读取监听信息失败',
  too_large: '采集器输出超出大小限制',
  malformed_output: '采集器输出格式无效',
  sample_changed: '两次端口采样结果不一致',
  identity_changed: '两次采样间监听进程身份发生变化',
  identity_read_failed: '无法核对监听进程身份',
  sampling_too_long: '端口采样耗时过长',
  clock_failed: '采集器时钟无法读取',
  boot_uuid_failed: '采集器启动会话无法读取',
  unknown: '未知',
};

const failureLabels: Record<PortObservationDisplay['failure'], string> = {
  none: '未报告失败',
  unknown: '未知',
  root_observer_path: '无法安全读取端口观察文件',
  root_observer_metadata: '无法核对端口观察文件信息',
  root_observer_read: '读取端口观察文件失败',
  root_observer_size: '端口观察文件超出大小限制',
  root_observer_changed: '读取期间端口观察文件发生变化',
  root_observer_unavailable: '端口观察服务不可用',
  root_observer_schema: '端口观察数据结构无效',
  root_observer_boot: '系统启动会话不一致',
  boot_uuid: '系统启动会话无法核对',
  monotonic_clock: '单调时钟无法核对',
  root_observer_stale: '端口观察记录已过期',
  root_observer_listener: '端口监听记录无效',
  root_observer_missing_listener: '端口观察记录未报告监听器',
  root_observer_netstat_read_failed: '旧格式采集器读取监听信息失败',
  root_observer_spawn_failed: '采集器无法启动监听读取工具',
  root_observer_lsof_read_failed: '采集器读取监听信息失败',
  root_observer_too_large: '采集器输出超出大小限制',
  root_observer_malformed_output: '采集器输出格式无效',
  root_observer_sample_changed: '两次端口采样结果不一致',
  root_observer_identity_changed: '两次采样间监听进程身份发生变化',
  root_observer_identity_read_failed: '无法核对监听进程身份',
  root_observer_sampling_too_long: '端口采样耗时过长',
  root_observer_clock_failed: '采集器时钟无法读取',
  root_observer_boot_uuid_failed: '采集器启动会话无法读取',
  ingress_process_changed: '入口进程身份与记录不一致',
  ingress_process_identity: '无法核对入口进程身份',
};

function portObservationTime(value: number | null, locale: 'zh' | 'en', t: (key: string) => string): string {
  if (value === null) return t('未知');
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return t('未知');
  return new Intl.DateTimeFormat(locale === 'zh' ? 'zh-CN' : 'en-US', {
    dateStyle: 'medium', timeStyle: 'medium',
  }).format(date);
}

export function GuardHome() {
  const { t, locale } = useI18n();
  const nativeBridge = isTauri();
  const [snapshot, setSnapshot] = useState<GuardSnapshot>(initialGuardSnapshot);
  const [selectedTarget, setSelectedTarget] = useState<GuardTargetId | ''>('');
  const [pending, setPending] = useState<Command | ''>(nativeBridge ? 'guard_status' : '');
  const [error, setError] = useState('');
  const [hasNativeSnapshot, setHasNativeSnapshot] = useState(false);
  const live = useRef(false);
  const pendingRef = useRef<Command | ''>('');
  const generation = useRef(0);

  async function run(command: Command, args?: { target: GuardTargetId }) {
    const previous = pendingRef.current;
    const priorityLock = command === 'guard_lock' && previous !== '' && previous !== 'guard_lock';
    if (!nativeBridge || (previous !== '' && !priorityLock)) return;
    const request = ++generation.current;
    pendingRef.current = command;
    setPending(command);
    setError('');
    try {
      const value = await invoke<unknown>(command, args);
      if (!isGuardSnapshot(value)) throw new Error(t('原生保护状态格式无效'));
      if (live.current && isLatestGuardRequest(request, generation.current)) { setSnapshot(value); setHasNativeSnapshot(true); }
    } catch (cause) {
      if (live.current && isLatestGuardRequest(request, generation.current)) setError(String(cause));
    } finally {
      if (isLatestGuardRequest(request, generation.current)) {
        pendingRef.current = '';
        if (live.current) setPending('');
      }
    }
  }

  useEffect(() => {
    live.current = true;
    if (nativeBridge) void run('guard_status');
    return () => { live.current = false; };
  }, [nativeBridge]);

  useEffect(() => {
    if (!nativeBridge) return;
    const timer = window.setInterval(() => {
      if (pendingRef.current === '') void run('guard_status');
    }, 1000);
    return () => window.clearInterval(timer);
  }, [nativeBridge]);

  useEffect(() => {
    if (snapshot.targets.some(target => target.id === selectedTarget && target.available)) return;
    setSelectedTarget(snapshot.targets.find(target => target.available)?.id ?? '');
  }, [snapshot.targets, selectedTarget]);

  const startAllowed = nativeBridge && canStartGuard(snapshot, selectedTarget) && !pending;
  const lockAllowed = nativeBridge && pending !== 'guard_lock' && (canLockGuard(snapshot) || pending === 'guard_start' || pending === 'guard_inspect');
  const recoverAllowed = nativeBridge && hasNativeSnapshot && canRecoverGuard(snapshot) && !pending;
  const verifiedActive = nativeBridge && snapshot.state === 'active' && snapshot.enforcementVerified;
  const portObservation = normalizePortObservation(snapshot.portObservation);
  const events = snapshot.events.slice(-200);

  return <section className="guard-page">
    <div className="cleanup-title"><div><h1>{t('保护中心')}</h1><p>{t('网络保护')}</p></div></div>
    {error && <p className="system-feedback error" role="alert">{t('保护命令失败：{error}', { error })}</p>}
    <div className="guard-grid">
      <Panel className="guard-card guard-protection-card">
        <PanelHeader title={<span className="system-card-title"><span className={`guard-state-dot ${verifiedActive ? 'verified' : ''}`} aria-hidden="true" />{t('保护状态')}</span>} />
        <div className="guard-card-body">
          <div className={`guard-state-value ${verifiedActive ? 'verified' : ''}`} role="status" aria-live="polite">{!nativeBridge ? t('静态预览：未连接原生保护服务') : pending === 'guard_status' ? t('正在读取保护状态…') : !hasNativeSnapshot ? t('无法读取保护状态') : stateLabel(snapshot, t)}</div>
          {nativeBridge && hasNativeSnapshot && snapshot.reason && snapshot.reason !== 'NotConfigured' && <p className="guard-reason">{t(snapshot.reason)}</p>}
          {nativeBridge && snapshot.state === 'active' && !snapshot.enforcementVerified && <p className="guard-reason">{t('Guard 报告正在运行，但当前原生运行前提尚未验证。')}</p>}
          <p className="guard-reason">{t('准备／恢复会经受管代理向 ipinfo.io 与 Cloudflare 发起 HTTPS 请求以核验出口。服务会看到代理出口 IP；此操作不会启动 Claude 或其他目标。')}</p>
          <p className="guard-reason">{t('三秒许可在 Rust 续期源停止后到期；React 界面卡住不一定会停止 Rust 续期。')}</p>
          <div className="guard-action-row">
            <Button size="small" variant="secondary" loading={pending === 'guard_status'} disabled={!nativeBridge || !!pending} onClick={() => void run('guard_status')}>{t('刷新状态')}</Button>
            <Button size="small" variant="secondary" loading={pending === 'guard_inspect'} disabled={!nativeBridge || !!pending} onClick={() => void run('guard_inspect')}>{t('检查防护')}</Button>
            <Button size="small" variant="ink" loading={pending === 'guard_start'} disabled={!startAllowed} onClick={() => { if (selectedTarget) void run('guard_start', { target: selectedTarget }); }}>{t('启动保护')}</Button>
            <Button size="small" variant="secondary" loading={pending === 'guard_lock'} disabled={!lockAllowed} onClick={() => void run('guard_lock')}>{t('锁定保护')}</Button>
            <Button size="small" variant="secondary" loading={pending === 'guard_recover'} disabled={!recoverAllowed} onClick={() => void run('guard_recover')}>{t('准备／恢复（不启动）')}</Button>
          </div>
          <fieldset className="guard-targets" disabled={!nativeBridge || !!pending}>
            <legend>{t('保护目标')}</legend>
            {!nativeBridge
              ? <p className="guard-empty">{t('静态预览：未连接原生保护服务')}</p>
              : snapshot.targets.length === 0
              ? <p className="guard-empty">{pending === 'guard_status' ? t('正在读取保护目标…') : hasNativeSnapshot ? t('原生状态中没有保护目标。') : t('尚未读取')}</p>
              : snapshot.targets.map(target => {
                const selectable = target.available;
                return <label className={`guard-target ${selectable ? '' : 'unavailable'}`} key={target.id}>
                  <input type="radio" name="guard-target" value={target.id} checked={selectedTarget === target.id} disabled={!selectable} onChange={() => setSelectedTarget(target.id)} />
                  <span className="guard-target-copy"><strong>{t(target.label)}</strong><span className="guard-target-meta"><small>{selectable ? t('可用') : t('不可用')}</small>{target.reason && <small className="guard-target-reason">{t(target.reason)}</small>}</span></span>
                </label>;
              })}
          </fieldset>
        </div>
      </Panel>

      <Panel className="guard-card guard-environment-card">
        <PanelHeader title={t('环境观测')} />
        <dl className="guard-environment">
          <div><dt>{t('运行平台')}</dt><dd>{!nativeBridge || !hasNativeSnapshot ? t('尚未读取') : snapshot.platform}</dd></div>
          <div><dt>{t('原生观测 IP')}</dt><dd>{!nativeBridge || !hasNativeSnapshot ? t('尚未读取') : snapshot.observedIp === null ? t('尚未观测') : snapshot.observedIp}</dd></div>
          <div><dt>{t('观测时间')}</dt><dd>{!nativeBridge || !hasNativeSnapshot ? t('尚未读取') : snapshot.observedAt === null ? t('尚未观测') : snapshot.observedAt}</dd></div>
          <div><dt>{t('当前原生运行前提')}</dt><dd>{!nativeBridge || !hasNativeSnapshot ? t('尚未读取') : t(runtimePrerequisiteLabelKey(snapshot.enforcementVerified))}</dd></div>
          <div><dt>{t('工件平台验收记录')}</dt><dd>{t('此界面未收到与当前工件绑定的平台验收记录。')}</dd></div>
          {nativeBridge && hasNativeSnapshot && <>
            <div><dt>{t('端口观察诊断')}</dt><dd>{t('只用于诊断，不代表流量已受保护、许可有效或平台验收通过。')}</dd></div>
            <div><dt>{t('观察文件')}</dt><dd>{t(portObservationLabels.fileState[portObservation.fileState])}</dd></div>
            <div><dt>{t('观察数据结构')}</dt><dd>{t(portObservationLabels.schemaState[portObservation.schemaState])}</dd></div>
            <div><dt>{t('采集器状态')}</dt><dd>{t(producerStatusLabels[portObservation.producerStatus])}</dd></div>
            <div><dt>{t('上游端口（7896）')}</dt><dd>{t(portObservationLabels.upstreamState[portObservation.upstreamState])}</dd></div>
            <div><dt>{t('Guard 入口（17897）')}</dt><dd>{t(portObservationLabels.ingressState[portObservation.ingressState])}</dd></div>
            <div><dt>{t('入口身份核对')}</dt><dd>{t(portObservationLabels.ingressOwnerState[portObservation.ingressOwnerState])}</dd></div>
            <div><dt>{t('启动会话核对')}</dt><dd>{t(portObservationLabels.bootState[portObservation.bootState])}</dd></div>
            <div><dt>{t('墙钟新鲜度')}</dt><dd>{t(portObservationLabels.wallFreshness[portObservation.wallFreshness])}</dd></div>
            <div><dt>{t('单调时钟新鲜度')}</dt><dd>{t(portObservationLabels.monotonicFreshness[portObservation.monotonicFreshness])}</dd></div>
            <div><dt>{t('端口观察时间')}</dt><dd>{portObservationTime(portObservation.observedAtUnixMs, locale, t)}</dd></div>
            <div><dt>{t('观察失败原因')}</dt><dd>{t(failureLabels[portObservation.failure])}</dd></div>
          </>}
        </dl>
      </Panel>

      <Panel className="guard-card guard-events-card">
        <PanelHeader title={t('保护执行记录')} subtitle={t('最近 {count} 条事件', { count: events.length })} />
        <div className="guard-terminal" role="log" aria-label={t('保护执行记录')} aria-live="off">
          {events.length === 0 ? <p className="guard-terminal-empty">{!nativeBridge ? t('静态预览：未连接原生保护服务') : hasNativeSnapshot ? t('暂无原生事件记录。') : t('尚未读取')}</p> : events.map((event, index) => <div className="guard-event" key={`${event.sequence}-${index}`}>
            <span className="guard-event-sequence">{String(event.sequence).padStart(4, '0')}</span>
            <span className="guard-event-level">{event.level}</span>
            <span className="guard-event-message">{event.recordedAtUnixMs != null && <time dateTime={new Date(event.recordedAtUnixMs).toISOString()}>{new Date(event.recordedAtUnixMs).toLocaleTimeString(locale === 'zh' ? 'zh-CN' : 'en-US', { hour12: false })} · </time>}{t(event.message)}</span>
          </div>)}
        </div>
      </Panel>
    </div>
    <GuardPrivacy />
  </section>;
}
