import { useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { downloadAuthenticated } from '@/modules/admin/utils/authenticatedDownload';
import {
  clearAuditFilters,
  setAuditFilter,
  setAuditPage,
  setComplianceQuery,
} from '../store/complianceSlice';
import type { AuditLogFilters } from '../types/complianceTypes';
import { auditExportUrl } from '../utils/auditExportUrl';

export function useCompliancePage() {
  const dispatch = useAppDispatch();
  const token = useAppSelector((s) => s.auth?.token ?? null);
  const query = useAppSelector((s) => s.compliance.query);
  const filters = useAppSelector((s) => s.compliance.filters);
  const page = useAppSelector((s) => s.compliance.page);
  const [isExporting, setIsExporting] = useState(false);

  const setQuery = (q: string) => dispatch(setComplianceQuery(q));
  const setFilter = (key: keyof AuditLogFilters, value: string) =>
    dispatch(setAuditFilter({ key, value }));
  const clearFilters = () => dispatch(clearAuditFilters());
  const setPage = (next: number) => dispatch(setAuditPage(next));

  // Export the full CSV via the authenticated download helper. Passes the active
  // action/resource filters so the export matches what the viewer shows.
  const onExport = async () => {
    setIsExporting(true);
    const params: Record<string, string> = {};
    if (filters.action) params.action = filters.action;
    if (filters.resource) params.resource = filters.resource;
    const status = await downloadAuthenticated(auditExportUrl(params), token);
    setIsExporting(false);
    if (status === 403) {
      toast.error('You do not have permission to export the audit log.');
    } else if (status === 401) {
      toast.error('Your session has expired. Sign in again.');
    } else if (status === 0 || status >= 400) {
      toast.error('Export failed. Try again.');
    }
  };

  return {
    query,
    setQuery,
    filters,
    setFilter,
    clearFilters,
    page,
    setPage,
    onExport,
    isExporting,
  };
}
