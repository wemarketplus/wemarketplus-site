import { toast } from 'sonner';
import type { ReportDefinition } from '../types/clReportsTypes';

export function useReportCard(report: ReportDefinition) {
  const onRun = () => toast.message(`${report.title} — export pending backend`);
  return { onRun };
}
