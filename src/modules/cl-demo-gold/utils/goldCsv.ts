// Pure CSV builder for the Gold reports export. Returns a string; the actual
// download (Blob + anchor click) is a side effect handled by useCsvDownload.
import type { Apartment, Lead } from '../types/goldTypes';
import { activeLeadCount, countAptStatus, occupancyRate } from './goldFormat';

// Reproduces exportGoldReport()'s row set verbatim.
export function buildGoldReportCsv(apts: readonly Apartment[], leads: readonly Lead[]): string {
  const rows = ['Category,Metric,Value'];
  rows.push('Occupancy,Current Rate,' + occupancyRate(apts) + '%');
  rows.push('Sales,Active Leads,' + activeLeadCount(leads));
  rows.push('Operations,Available Units,' + countAptStatus(apts, 'available'));
  apts.forEach((a) => {
    rows.push('Apartment,Unit ' + a.unit + ' Status,' + a.status.replace(/_/g, ' '));
  });
  return rows.join('\n');
}
