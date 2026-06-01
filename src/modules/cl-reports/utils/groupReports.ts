import type { ReportDefinition } from '../types/clReportsTypes';

export function groupReportsByCategory(
  reports: readonly ReportDefinition[],
): Record<ReportDefinition['category'], ReportDefinition[]> {
  const acc: Record<string, ReportDefinition[]> = {};
  for (const r of reports) (acc[r.category] ??= []).push(r);
  return acc as Record<ReportDefinition['category'], ReportDefinition[]>;
}
