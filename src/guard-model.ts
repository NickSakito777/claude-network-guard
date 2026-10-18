/**
 * [INPUT]: Native Guard snapshot returned by the Tauri command boundary.
 * [OUTPUT]: Validated snapshot types, event recording times, and state-based action availability.
 * [POS]: Shared, side-effect-free contract for the Guard home and its tests.
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
export const guardTargetIds = ['claude', 'sunbrowser', 'ccbaga_browser', 'claude_code', 'mcp'] as const;
export type GuardTargetId = typeof guardTargetIds[number];
export type GuardState = 'unavailable' | 'locked' | 'checking' | 'active' | 'recovery';
export type GuardTarget = { id: GuardTargetId; label: string; available: boolean; reason: string | null };
export type GuardEvent = { sequence: number; recordedAtUnixMs?: number | null; level: string; message: string };
export type PortObservationDisplay = {
  fileState: 'unreadable' | 'invalid' | 'readable' | 'unknown';
  schemaState: 'unavailable' | 'invalid' | 'valid' | 'unknown';
  producerStatus:
    | 'ok' | 'missing_listener' | 'netstat_read_failed' | 'netstat_spawn_failed' | 'netstat_too_large'
    | 'spawn_failed' | 'lsof_read_failed' | 'too_large' | 'malformed_output'
    | 'sample_changed' | 'identity_changed' | 'identity_read_failed'
    | 'sampling_too_long' | 'clock_failed' | 'boot_uuid_failed' | 'unknown';
  upstreamState: 'unavailable' | 'missing' | 'invalid' | 'present' | 'unknown';
  ingressState: 'unavailable' | 'missing' | 'invalid' | 'present' | 'unknown';
  ingressOwnerState: 'unchecked' | 'unavailable' | 'matches' | 'mismatch' | 'unknown';
  bootState: 'unavailable' | 'invalid' | 'matches' | 'mismatch' | 'unknown';
  wallFreshness: 'unavailable' | 'invalid' | 'fresh' | 'stale' | 'future' | 'unknown';
  monotonicFreshness: 'unavailable' | 'invalid' | 'fresh' | 'stale' | 'future' | 'unknown';
  observedAtUnixMs: number | null;
  failure:
    | 'none' | 'unknown'
    | 'root_observer_path' | 'root_observer_metadata' | 'root_observer_read' | 'root_observer_size'
    | 'root_observer_changed' | 'root_observer_unavailable' | 'root_observer_schema'
    | 'root_observer_boot' | 'boot_uuid' | 'monotonic_clock' | 'root_observer_stale'
    | 'root_observer_listener' | 'root_observer_missing_listener'
    | 'root_observer_netstat_read_failed' | 'root_observer_spawn_failed'
    | 'root_observer_lsof_read_failed' | 'root_observer_too_large'
    | 'root_observer_malformed_output' | 'root_observer_sample_changed'
    | 'root_observer_identity_changed' | 'root_observer_identity_read_failed'
    | 'root_observer_sampling_too_long' | 'root_observer_clock_failed'
    | 'root_observer_boot_uuid_failed'
    | 'ingress_process_changed' | 'ingress_process_identity';
};

export type GuardSnapshot = {
  schemaVersion: 1;
  platform: string;
  state: GuardState;
  reason: string | null;
  targets: GuardTarget[];
  /** Current native readback fact; it does not represent artifact or platform acceptance. */
  enforcementVerified: boolean;
  observedIp: string | null;
  observedAt: string | null;
  /** Optional, nullable, display-only data; legacy snapshots can omit it. */
  portObservation?: unknown;
  events: GuardEvent[];
};

/** UI copy key for the current native runtime prerequisite readback. */
export function runtimePrerequisiteLabelKey(enforcementVerified: boolean): '当前运行前提已核对' | '当前运行前提尚未验证' {
  return enforcementVerified ? '当前运行前提已核对' : '当前运行前提尚未验证';
}

const states = new Set<GuardState>(['unavailable', 'locked', 'checking', 'active', 'recovery']);
const targetIds = new Set<string>(guardTargetIds);

export function initialGuardSnapshot(): GuardSnapshot {
  return {
    schemaVersion: 1,
    platform: 'unknown',
    state: 'unavailable',
    reason: 'NotConfigured',
    targets: [],
    enforcementVerified: false,
    observedIp: null,
    observedAt: null,
    portObservation: null,
    events: [],
  };
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

const fileStates = ['unreadable', 'invalid', 'readable'] as const;
const schemaStates = ['unavailable', 'invalid', 'valid'] as const;
const producerStatuses = [
  'ok', 'missing_listener', 'netstat_read_failed', 'netstat_spawn_failed', 'netstat_too_large',
  'spawn_failed', 'lsof_read_failed', 'too_large', 'malformed_output',
  'sample_changed', 'identity_changed', 'identity_read_failed', 'sampling_too_long',
  'clock_failed', 'boot_uuid_failed',
] as const;
const portStates = ['unavailable', 'missing', 'invalid', 'present'] as const;
const ownerStates = ['unchecked', 'unavailable', 'matches', 'mismatch'] as const;
const bootStates = ['unavailable', 'invalid', 'matches', 'mismatch'] as const;
const freshnessStates = ['unavailable', 'invalid', 'fresh', 'stale', 'future'] as const;
const failureCodes = [
  'root_observer_path', 'root_observer_metadata', 'root_observer_read', 'root_observer_size',
  'root_observer_changed', 'root_observer_unavailable', 'root_observer_schema',
  'root_observer_boot', 'boot_uuid', 'monotonic_clock', 'root_observer_stale',
  'root_observer_listener', 'root_observer_missing_listener',
  'root_observer_netstat_read_failed', 'root_observer_spawn_failed',
  'root_observer_lsof_read_failed', 'root_observer_too_large',
  'root_observer_malformed_output', 'root_observer_sample_changed',
  'root_observer_identity_changed', 'root_observer_identity_read_failed',
  'root_observer_sampling_too_long', 'root_observer_clock_failed',
  'root_observer_boot_uuid_failed',
  'ingress_process_changed', 'ingress_process_identity',
] as const;

function enumValue<const T extends readonly string[]>(value: unknown, values: T): T[number] | 'unknown' {
  return typeof value === 'string' && (values as readonly string[]).includes(value)
    ? value as T[number]
    : 'unknown';
}

function observedPortState(value: unknown): PortObservationDisplay['upstreamState'] {
  return enumValue(value, portStates);
}

function unknownPortObservation(): PortObservationDisplay {
  return {
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
  };
}

/** Normalize diagnostics at the display boundary; none of these values affect action gates or proof. */
export function normalizePortObservation(value: unknown): PortObservationDisplay {
  if (!record(value) || value.diagnosticOnly !== true) return unknownPortObservation();
  const fileState = enumValue(value.fileState, fileStates);
  const schemaState = enumValue(value.schemaState, schemaStates);
  const producerStatus = enumValue(value.producerStatus, producerStatuses);
  const rawFailure = value.failure;
  const failure = rawFailure === null
    ? 'none'
    : enumValue(rawFailure, failureCodes);

  return {
    fileState,
    schemaState,
    producerStatus,
    upstreamState: observedPortState(value.upstreamState),
    ingressState: observedPortState(value.ingressState),
    ingressOwnerState: enumValue(value.ingressOwnerState, ownerStates),
    bootState: enumValue(value.bootState, bootStates),
    wallFreshness: enumValue(value.wallFreshness, freshnessStates),
    monotonicFreshness: enumValue(value.monotonicFreshness, freshnessStates),
    observedAtUnixMs: typeof value.observedAtUnixMs === 'number'
      && Number.isSafeInteger(value.observedAtUnixMs) && value.observedAtUnixMs > 0
      ? value.observedAtUnixMs
      : null,
    failure,
  };
}

function isTarget(value: unknown): value is GuardTarget {
  return record(value)
    && typeof value.id === 'string' && targetIds.has(value.id)
    && typeof value.label === 'string'
    && typeof value.available === 'boolean'
    && nullableString(value.reason);
}

function isEvent(value: unknown): value is GuardEvent {
  return record(value)
    && typeof value.sequence === 'number' && Number.isSafeInteger(value.sequence) && value.sequence >= 0
    && (value.recordedAtUnixMs == null || (typeof value.recordedAtUnixMs === 'number'
      && Number.isSafeInteger(value.recordedAtUnixMs) && value.recordedAtUnixMs > 0
      && value.recordedAtUnixMs <= 8_640_000_000_000_000))
    && typeof value.level === 'string'
    && typeof value.message === 'string';
}

export function isGuardSnapshot(value: unknown): value is GuardSnapshot {
  if (!record(value) || value.schemaVersion !== 1 || typeof value.platform !== 'string'
    || typeof value.state !== 'string' || !states.has(value.state as GuardState)
    || !nullableString(value.reason) || !Array.isArray(value.targets) || !Array.isArray(value.events)
    || typeof value.enforcementVerified !== 'boolean' || !nullableString(value.observedIp)
    || !nullableString(value.observedAt) || !value.targets.every(isTarget) || !value.events.every(isEvent)) {
    return false;
  }
  return new Set(value.targets.map(target => target.id)).size === value.targets.length;
}

export function canStartGuard(snapshot: GuardSnapshot, targetId: GuardTargetId | ''): boolean {
  return (snapshot.state === 'locked' || snapshot.state === 'active')
    && !!targetId
    && snapshot.targets.some(target => target.id === targetId && target.available);
}

export function canLockGuard(snapshot: GuardSnapshot): boolean {
  return snapshot.state === 'active' || snapshot.state === 'checking' || snapshot.state === 'recovery';
}

export function canRecoverGuard(snapshot: GuardSnapshot): boolean {
  return snapshot.state === 'unavailable' || snapshot.state === 'recovery' || snapshot.state === 'locked';
}

export function isLatestGuardRequest(request: number, latest: number): boolean {
  return request === latest;
}
