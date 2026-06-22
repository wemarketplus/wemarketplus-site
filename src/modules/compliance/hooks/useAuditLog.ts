import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { useListAuditLogQuery } from '../api/complianceApi';
import { AUDIT_FIXTURE } from '../constants/complianceConstants';
import { filterAuditLog, mapAuditLogItem } from '../utils/complianceUtils';

// Reads the live audit log (GET /audit) and falls back to the illustrative
// fixture only when the tenant has no audit events yet, so a fresh workspace
// doesn't show an empty table. Search filtering runs client-side over whichever
// source is active.
export function useAuditLog() {
  const { data } = useListAuditLogQuery({ page: 1, limit: 100 });
  const query = useAppSelector((s) => s.compliance.query);
  const debounced = useDebounce(query, 200);

  const source = useMemo(
    () =>
      data && data.data.length > 0 ? data.data.map(mapAuditLogItem) : AUDIT_FIXTURE,
    [data],
  );

  const entries = useMemo(
    () => filterAuditLog(source, debounced),
    [source, debounced],
  );

  return {
    entries,
    total: source.length,
    isUsingFixture: !data || data.data.length === 0,
  };
}
