// Pure CSV builder for the Max reports export (reference exportGoldReport()).
import type { Apartment, Lead } from '../types/maxTypes';
import { activeLeadCount, countAptStatus, occupancyRate } from './maxFormat';

export function buildMaxReportCsv(apts: readonly Apartment[], leads: readonly Lead[]): string {
  const rows = ['Category,Metric,Value'];
  rows.push('Occupancy,Current Rate,' + occupancyRate(apts) + '%');
  rows.push('Sales,Active Leads,' + activeLeadCount(leads));
  rows.push('Operations,Available Units,' + countAptStatus(apts, 'available'));
  apts.forEach((a) => {
    rows.push('Apartment,Unit ' + a.unit + ' Status,' + a.status.replace(/_/g, ' '));
  });
  return rows.join('\n');
}
