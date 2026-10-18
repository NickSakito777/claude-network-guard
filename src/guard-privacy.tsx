/** Read-only telemetry configuration display; never grants or launches protection. */
import { invoke, isTauri } from '@tauri-apps/api/core';
import { Button, Panel, PanelHeader } from 'cromma-ui';
import { useState } from 'react';
import { useI18n } from './i18n';

type Client = {
  installedVersion: string | null;
  auditedVersion: string;
  versionScope: string;
  channels: { channel: string; state: 'configured_off' | 'open' | 'unknown' }[];
};
type PrivacySnapshot = { desktop: Client; cli: Client; runtimeVerified: boolean };
const names: Record<string, string> = {
  desktop_sentry: '桌面端错误与崩溃报告',
  desktop_product_and_diagnostic_events: '桌面端产品事件与诊断',
  desktop_auto_updates: '桌面端更新检查',
  desktop_otlp_export: '桌面端企业遥测导出',
  cli_first_party_events: 'Code 产品事件',
  cli_datadog_logs: 'Code Datadog 日志',
  cli_datadog_errors: 'Code 错误追踪',
  cli_internal_metrics: 'Code 内部指标',
  cli_growthbook: 'Code 实验配置',
  cli_otel_exporters: 'Code 自定义遥测导出',
  cli_beta_tracing: 'Code 增强追踪',
  cli_remote_gateway_otlp_relay: 'Code 远程与网关遥测中继',
  cli_model_requests: '正常模型请求',
};
export function GuardPrivacy() {
  const { t } = useI18n();
  const [snapshot, setSnapshot] = useState<PrivacySnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function inspect() {
    setBusy(true); setError('');
    try { setSnapshot(await invoke<PrivacySnapshot>('guard_privacy_inspect')); }
    catch (cause) { setSnapshot(null); setError(String(cause)); }
    finally { setBusy(false); }
  }
  return <Panel className="guard-privacy-card">
    <PanelHeader title={t('遥测与隐私')} actions={<Button size="small" variant="secondary" loading={busy} disabled={!isTauri() || busy} onClick={() => void inspect()}>{t('读取配置')}</Button>} />
    <p className="system-hint" role="status">{t('遥测外发尚未实测；配置读回与网络保护分别核验。')}</p>
    {error && <p className="system-feedback error" role="alert">{error}</p>}
    {!snapshot ? <p className="system-hint">{t('读取客户端版本与遥测配置，不修改设置或启动应用。')}</p> : <details>
      <summary>{t('查看遥测渠道与客户端版本')}</summary>
      {([['Claude Desktop', snapshot.desktop], ['Claude Code', snapshot.cli]] as const).map(([label, client]) => <section key={label}>
        <h3>{t(label)}</h3>
        <p className="system-hint">{t('已安装：{installed}；参考审计：{audited}', { installed: client.installedVersion ?? t('未知'), audited: client.auditedVersion })}</p>
        {client.versionScope !== 'audit_version' && <p className="system-hint">{t('版本尚未完成对应复验。')}</p>}
        <dl className="guard-environment">{client.channels.map(channel => <div key={channel.channel}>
          <dt>{t(names[channel.channel] ?? channel.channel)}</dt>
          <dd>{t(channel.state === 'configured_off' ? '配置要求关闭' : channel.state === 'open' ? '配置允许发送' : '有效状态未知')}</dd>
        </div>)}</dl>
      </section>)}
    </details>}
  </Panel>;
}
