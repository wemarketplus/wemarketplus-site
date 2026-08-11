import type { AuditLogEntry } from '../types/complianceTypes';
import type { AuditLogItem } from '../types/complianceApiTypes';

// Maps a backend audit record (AuditLogItem) onto the table's view-model.
//
// The actor is the resolved NAME the backend sends, not the raw uuid this used
// to render: "who logged in and what they changed" is the whole point of the
// screen, and a uuid answers neither. The id is kept alongside so support can
// still correlate a row against the API.
//
// The IP comes from `meta.ip`, which AuditService now populates on every row
// from the request context (it was previously written only by the auth flow, so
// this column rendered "—" for everything else).
export function mapAuditLogItem(item: AuditLogItem): AuditLogEntry {
  const target = item.resourceId ?? '—';
  const ip = typeof item.meta?.ip === 'string' ? item.meta.ip : '—';
  return {
    id: item.id,
    actor: item.actorName,
    actorEmail: item.actorEmail,
    actorId: item.userId,
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
      // Email and raw id stay searchable even though the column now shows a
      // name: an operator investigating an incident typically has one of those
      // from a log or a ticket, not the person's display name.
      (e.actorEmail?.toLowerCase().includes(needle) ?? false) ||
      (e.actorId?.toLowerCase().includes(needle) ?? false) ||
      e.action.toLowerCase().includes(needle) ||
      e.resource.toLowerCase().includes(needle) ||
      e.target.toLowerCase().includes(needle) ||
      e.meta.toLowerCase().includes(needle),
  );
}
