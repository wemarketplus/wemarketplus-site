import { REPORT_CATALOG } from '../constants/clReportsConstants';
import { groupReportsByCategory } from '../utils/groupReports';

export function useReportCatalog() {
  return {
    reports: REPORT_CATALOG,
    grouped: groupReportsByCategory(REPORT_CATALOG),
    isUsingFixture: true,
  };
}
