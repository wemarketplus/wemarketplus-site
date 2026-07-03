import type { AuditLogEntry } from '../types/complianceTypes';
import type { AuditLogItem } from '../types/complianceApiTypes';

// Maps a backend audit record (AuditLogItem) onto the table's view-model. The
// backend has no display name/IP columns, so we derive a readable target from
// resource/resourceId and surface the IP from meta when the logger captured it.
export function mapAuditLogItem(item: AuditLogItem): AuditLogEntry {
  const target = item.resourceId ?? '—';
  const ip = typeof item.meta?.ip === 'string' ? item.meta.ip : '—';
  return {
    id: item.id,
    actor: item.userId ?? 'system',
    action: item.action,
    resource: item.resource ?? '—',
    target,
    meta: summarizeMeta(item.meta),
    occurredAt: item.createdAt,
    ipAddress: ip,
  };
}

// Renders the audit meta blob as a compact single-line summary for the table
// (the full object is available in the raw export). Drops the ip key since it
// has its own column.
function summarizeMeta(meta: Record<string, unknown>): string {
  const entries = Object.entries(meta).filter(([key]) => key !== 'ip');
  if (entries.length === 0) return '—';
  return entries
    .map(([key, value]) => `${key}: ${formatMetaValue(value)}`)
    .join(', ');
}

function formatMetaValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export function filterAuditLog(
  entries: readonly AuditLogEntry[],
  query: string,
): readonly AuditLogEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return entries;
  return entries.filter(
    (e) =>
      e.actor.toLowerCase().includes(needle) ||
      e.action.toLowerCase().includes(needle) ||
      e.resource.toLowerCase().includes(needle) ||
      e.target.toLowerCase().includes(needle) ||
      e.meta.toLowerCase().includes(needle),
  );
}
