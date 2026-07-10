import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { useListAuditLogQuery } from '../api/complianceApi';
import { AUDIT_PAGE_SIZE } from '../constants/complianceConstants';
import { filterAuditLog, mapAuditLogItem } from '../utils/complianceUtils';

// Live, server-driven audit log viewer. Structured filters (action, resource,
// actor, date range) and pagination are sent to GET /audit; the free-text
// search box filters the current page client-side. Loading and error states
// are surfaced so the page can render them explicitly rather than showing a
// misleading empty table.
export function useAuditLog() {
  const query = useAppSelector((s) => s.compliance.query);
  const filters = useAppSelector((s) => s.compliance.filters);
  const page = useAppSelector((s) => s.compliance.page);
  const debounced = useDebounce(query, 200);

  // Normalize a date-only bound to a full-day range so the upper bound is
  // inclusive (2026-07-03 -> up to 2026-07-03T23:59:59Z).
  const dateTo = filters.dateTo ? `${filters.dateTo}T23:59:59.999Z` : '';

  const { data, isFetching, isError, refetch } = useListAuditLogQuery({
    page,
    limit: AUDIT_PAGE_SIZE,
    action: filters.action,
    resource: filters.resource,
    userId: filters.userId,
    dateFrom: filters.dateFrom,
    dateTo,
  });

  const pageEntries = useMemo(
    () => (data ? data.data.map(mapAuditLogItem) : []),
    [data],
  );

  const entries = useMemo(
    () => filterAuditLog(pageEntries, debounced),
    [pageEntries, debounced],
  );

  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE));

  return {
    entries,
    total,
    page,
    pageCount,
    pageSize: AUDIT_PAGE_SIZE,
    isFetching,
    isError,
    refetch,
  };
}
