import type { AuditLogEntry } from '../types/complianceTypes';

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
