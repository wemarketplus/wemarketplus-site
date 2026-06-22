import type { AuditLogEntry } from '../types/complianceTypes';
import type { AuditLogItem } from '../types/complianceApiTypes';

// Maps a backend audit record (AuditLogItem) onto the table's view-model. The
// backend has no display name/IP columns, so we derive a readable target from
// resource/resourceId and surface the IP from meta when the logger captured it.
export function mapAuditLogItem(item: AuditLogItem): AuditLogEntry {
  const target =
    item.resource && item.resourceId
      ? `${item.resource} ${item.resourceId}`
      : (item.resource ?? '—');
  const ip = typeof item.meta?.ip === 'string' ? item.meta.ip : '—';
  return {
    id: item.id,
    actor: item.userId ?? 'system',
    action: item.action,
    target,
    occurredAt: item.createdAt,
    ipAddress: ip,
  };
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
      e.target.toLowerCase().includes(needle),
  );
}
