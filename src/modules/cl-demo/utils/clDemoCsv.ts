// Pure CSV builders for the demo's export buttons. They return strings; the
// actual download (Blob + anchor click) is a side effect handled in a hook.
import type { Lead, MileageEntry } from '../types/clDemoTypes';
import { reimbursable } from './clDemoFormat';

export function buildMileageCsv(mileage: readonly MileageEntry[]): string {
  const rows = ['Date,From,To,Miles,Purpose,Reimbursable'].concat(
    mileage.map((m) =>
      [m.date, m.from, m.to, m.miles, m.purpose, '$' + reimbursable(m.miles)].join(','),
    ),
  );
  return rows.join('\n');
}

export function buildLeadsReportCsv(leads: readonly Lead[]): string {
  const rows = ['Name,Care Level,Status,Urgency,Source,Follow-Up'].concat(
    leads.map((l) => [l.name, l.care, l.status, l.urgency, l.source, l.fu].join(',')),
  );
  return rows.join('\n');
}
