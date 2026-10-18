/**
 * [INPUT]: Synthetic Guard snapshots matching the native command contract.
 * [OUTPUT]: Regression checks for snapshot validation, runtime-proof scope, and safe action gates.
 * [POS]: Pure model tests; no Tauri command, network probe, or host mutation.
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import { expect, test } from 'bun:test';
import { canLockGuard, canRecoverGuard, canStartGuard, guardTargetIds, initialGuardSnapshot, isGuardSnapshot, isLatestGuardRequest, normalizePortObservation, runtimePrerequisiteLabelKey, type GuardSnapshot } from './guard-model';

const ready = (state: GuardSnapshot['state'] = 'locked'): GuardSnapshot => ({
  ...initialGuardSnapshot(),
  platform: 'macos',
  state,
  reason: null,
  enforcementVerified: true,
  targets: [{ id: 'claude', label: 'Claude', available: true, reason: null }],
});

test('runtime prerequisite copy marks a false readback as unverified, not unchecked', () => {
  expect(runtimePrerequisiteLabelKey(false)).toBe('当前运行前提尚未验证');
  expect(runtimePrerequisiteLabelKey(true)).toBe('当前运行前提已核对');
});

test('initial model is explicitly unavailable and does not invent targets or observations', () => {
  const snapshot = initialGuardSnapshot();
  expect(snapshot.state).toBe('unavailable');
  expect(snapshot.reason).toBe('NotConfigured');
  expect(snapshot.targets).toEqual([]);
  expect(snapshot.enforcementVerified).toBe(false);
  expect(snapshot.observedIp).toBeNull();
  expect(snapshot.observedAt).toBeNull();
});

test('failure events retain recording times and reject invalid dates; legacy events still render', () => {
  const event = { sequence: 1, level: 'error', message: 'probe failed' };
  const withEvent = (recordedAtUnixMs: unknown) => ({ ...ready(), events: [{ ...event, recordedAtUnixMs }] });
  expect(isGuardSnapshot(withEvent(1_792_041_071_000))).toBe(true);
  expect(isGuardSnapshot(withEvent(null))).toBe(true);
  expect(isGuardSnapshot({ ...ready(), events: [event] })).toBe(true);
  for (const invalid of [-1, 0, NaN, Infinity, 1.5, Number.MAX_SAFE_INTEGER, 'now']) {
    expect(isGuardSnapshot(withEvent(invalid))).toBe(false);
  }
});

test('start requires a locked or active snapshot and a native available target; runtime proof is not an acceptance result', () => {
  const locked = ready();
  expect(canStartGuard(locked, 'claude')).toBe(true);
  expect(canStartGuard(ready('active'), 'claude')).toBe(true);
  expect(canStartGuard(locked, 'mcp')).toBe(false);
  expect(canStartGuard(initialGuardSnapshot(), 'claude')).toBe(false);
  expect(canStartGuard({ ...initialGuardSnapshot(), targets: [{ ...locked.targets[0], id: 'claude' }] }, 'claude')).toBe(false);
  expect(canStartGuard({ ...locked, enforcementVerified: false }, 'claude')).toBe(true);
  expect(canStartGuard({ ...locked, state: 'checking' }, 'claude')).toBe(false);
  expect(canStartGuard({ ...locked, state: 'recovery' }, 'claude')).toBe(false);
  expect(canStartGuard({ ...locked, targets: [{ ...locked.targets[0], available: false }] }, 'claude')).toBe(false);
});

test('an egress observation does not create a runtime proof or artifact acceptance record', () => {
  const observationOnly = {
    ...initialGuardSnapshot(),
    platform: 'macos',
    state: 'locked' as const,
    reason: null,
    observedIp: '198.51.100.5',
    observedAt: '2026-10-15T09:00:00Z',
    targets: [{ id: 'claude' as const, label: 'Claude', available: true, reason: null }],
  };
  expect(isGuardSnapshot(observationOnly)).toBe(true);
  expect(observationOnly.enforcementVerified).toBe(false);
  expect(Object.hasOwn(observationOnly, 'artifactAcceptance')).toBe(false);
});

test('port observation is optional for legacy snapshots and is never authority', () => {
  const legacy = ready();
  expect(isGuardSnapshot(legacy)).toBe(true);
  expect(isGuardSnapshot({ ...legacy, portObservation: null })).toBe(true);
  expect(isGuardSnapshot({ ...legacy, portObservation: 'malformed diagnostic' })).toBe(true);
  expect(normalizePortObservation('malformed diagnostic').upstreamState).toBe('unknown');
  const unknownObservation = {
    fileState: 'unknown', schemaState: 'unknown', producerStatus: 'unknown',
    upstreamState: 'unknown', ingressState: 'unknown', ingressOwnerState: 'unknown',
    bootState: 'unknown', wallFreshness: 'unknown', monotonicFreshness: 'unknown',
    observedAtUnixMs: null, failure: 'unknown',
  } as const;
  expect(normalizePortObservation(undefined)).toEqual(unknownObservation);
  expect(normalizePortObservation(null)).toEqual(unknownObservation);
  expect(canStartGuard(legacy, 'claude')).toBe(true);
  const diagnostic = {
    diagnosticOnly: true,
    fileState: 'readable',
    schemaState: 'valid',
    producerStatus: 'ok',
    upstreamState: 'missing',
    ingressState: 'present',
    ingressOwnerState: 'matches',
    bootState: 'matches',
    wallFreshness: 'fresh',
    monotonicFreshness: 'fresh',
    observedAtUnixMs: 1_800_000_000_000,
    failure: null,
  };
  expect(normalizePortObservation({ ...diagnostic, diagnosticOnly: false }).upstreamState).toBe('unknown');
  expect(normalizePortObservation({ fileState: 'readable' }).ingressState).toBe('unknown');
  const withDiagnostic = { ...legacy, portObservation: diagnostic };
  expect(isGuardSnapshot(withDiagnostic)).toBe(true);
  expect(normalizePortObservation(diagnostic).upstreamState).toBe('missing');
  expect(canStartGuard(withDiagnostic, 'claude')).toBe(true);
  expect(withDiagnostic.enforcementVerified).toBe(true);
  expect(Object.hasOwn(withDiagnostic, 'artifactAcceptance')).toBe(false);
});

test('unknown and partial port observations normalize to unknown without echoing native strings', () => {
  const view = normalizePortObservation({
    diagnosticOnly: true,
    fileState: 'unknown /private/path',
    schemaState: 'new-schema',
    producerStatus: '/private/path/producer',
    upstreamState: 'pid-123',
    ingressState: null,
    ingressOwnerState: 'unexpected',
    bootState: undefined,
    wallFreshness: 'brand-new',
    monotonicFreshness: 'future-ish',
    observedAtUnixMs: 9_007_199_254_740_992,
    failure: '/private/path/user-1234',
  });
  expect(view).toEqual({
    fileState: 'unknown',
    schemaState: 'unknown',
    producerStatus: 'unknown',
    upstreamState: 'unknown',
    ingressState: 'unknown',
    ingressOwnerState: 'unknown',
    bootState: 'unknown',
    wallFreshness: 'unknown',
    monotonicFreshness: 'unknown',
    observedAtUnixMs: null,
    failure: 'unknown',
  });
  expect(JSON.stringify(view)).not.toContain('/private/path');
  expect(JSON.stringify(view)).not.toContain('1234');
});

test('native candidate failure samples survive the frontend display boundary without becoming authority', () => {
  const samples = [
    ['missing_listener', 'root_observer_missing_listener'],
    ['netstat_read_failed', 'root_observer_netstat_read_failed'],
    ['spawn_failed', 'root_observer_spawn_failed'],
    ['lsof_read_failed', 'root_observer_lsof_read_failed'],
    ['too_large', 'root_observer_too_large'],
    ['malformed_output', 'root_observer_malformed_output'],
    ['sample_changed', 'root_observer_sample_changed'],
    ['identity_changed', 'root_observer_identity_changed'],
    ['identity_read_failed', 'root_observer_identity_read_failed'],
    ['sampling_too_long', 'root_observer_sampling_too_long'],
    ['clock_failed', 'root_observer_clock_failed'],
    ['boot_uuid_failed', 'root_observer_boot_uuid_failed'],
  ] as const;

  for (const [producerStatus, failure] of samples) {
    // Mirrors the bounded diagnosticOnly payload after the Swift/Rust reader boundary.
    const wireSample = {
      diagnosticOnly: true, fileState: 'readable', schemaState: 'valid', producerStatus,
      upstreamState: 'unavailable', ingressState: 'unavailable',
      ingressOwnerState: 'unchecked', bootState: 'matches',
      wallFreshness: 'fresh', monotonicFreshness: 'fresh',
      observedAtUnixMs: 1_800_000_000_000, failure,
    };
    const view = normalizePortObservation(wireSample);
    expect(view.producerStatus).toBe(producerStatus);
    expect(view.failure).toBe(failure);
    expect(canStartGuard({ ...ready(), portObservation: wireSample }, 'claude')).toBe(true);
  }
});

test('legacy missing_listener with empty rows stays unavailable per port', () => {
  const view = normalizePortObservation({
    diagnosticOnly: true,
    fileState: 'readable',
    schemaState: 'invalid',
    producerStatus: 'missing_listener',
    upstreamState: 'unavailable',
    ingressState: 'unavailable',
    ingressOwnerState: 'unchecked',
    bootState: 'invalid',
    wallFreshness: 'invalid',
    monotonicFreshness: 'invalid',
    observedAtUnixMs: null,
    failure: 'root_observer_missing_listener',
  });
  expect(view.producerStatus).toBe('missing_listener');
  expect(view.upstreamState).toBe('unavailable');
  expect(view.ingressState).toBe('unavailable');
  expect(view.observedAtUnixMs).toBeNull();
  expect(view.failure).toBe('root_observer_missing_listener');
});

test('reader-confirmed missing survives unrelated producer and schema diagnostics', () => {
  const view = normalizePortObservation({
    diagnosticOnly: true,
    fileState: 'readable',
    schemaState: 'invalid',
    producerStatus: 'netstat_read_failed',
    upstreamState: 'missing',
    ingressState: 'unavailable',
    ingressOwnerState: 'unchecked',
    bootState: 'unavailable',
    wallFreshness: 'unavailable',
    monotonicFreshness: 'unavailable',
    observedAtUnixMs: null,
    failure: 'root_observer_read',
  });
  expect(view.upstreamState).toBe('missing');
  expect(view.ingressState).toBe('unavailable');
});

test('lock and recovery buttons follow only the snapshot state', () => {
  expect(canLockGuard(ready('active'))).toBe(true);
  expect(canLockGuard(ready('checking'))).toBe(true);
  expect(canLockGuard(ready('recovery'))).toBe(true);
  expect(canLockGuard(ready('locked'))).toBe(false);
  expect(canRecoverGuard(ready('recovery'))).toBe(true);
  expect(canRecoverGuard(ready('locked'))).toBe(true);
  expect(canRecoverGuard(initialGuardSnapshot())).toBe(true);
  expect(canRecoverGuard(ready('active'))).toBe(false);
});

test('target selection follows native availability without target-specific UI policy', () => {
  const snapshot = {
    ...ready(),
    targets: [
      { id: 'claude_code' as const, label: 'Claude Code', available: true, reason: null },
      { id: 'mcp' as const, label: 'MCP', available: false, reason: 'No verified adapter.' },
    ],
  };
  expect(canStartGuard(snapshot, 'claude_code')).toBe(true);
  expect(canStartGuard(snapshot, 'mcp')).toBe(false);
});

test('snapshot validator accepts the contract and rejects malformed or unknown native values', () => {
  const snapshot = { ...ready(), events: [{ sequence: 4, level: 'info', message: 'guard inspected' }] };
  expect(guardTargetIds).toEqual(['claude', 'sunbrowser', 'ccbaga_browser', 'claude_code', 'mcp']);
  expect(isGuardSnapshot(snapshot)).toBe(true);
  expect(isGuardSnapshot({ ...snapshot, schemaVersion: 2 })).toBe(false);
  expect(isGuardSnapshot({ ...snapshot, state: 'passed' })).toBe(false);
  expect(isGuardSnapshot({ ...snapshot, targets: [{ ...snapshot.targets[0], id: 'unknown' }] })).toBe(false);
  expect(isGuardSnapshot({ ...snapshot, targets: [snapshot.targets[0], snapshot.targets[0]] })).toBe(false);
  expect(isGuardSnapshot({ ...snapshot, events: [{ sequence: Number.NaN, level: 'info', message: 'bad' }] })).toBe(false);
});

test('a superseded command response cannot replace a newer lock snapshot', () => {
  expect(isLatestGuardRequest(8, 8)).toBe(true);
  expect(isLatestGuardRequest(7, 8)).toBe(false);
});
