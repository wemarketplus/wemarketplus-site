import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { AUDIT_FIXTURE } from '../constants/complianceConstants';
import { filterAuditLog } from '../utils/complianceUtils';

export function useAuditLog() {
  const query = useAppSelector((s) => s.compliance.query);
  const debounced = useDebounce(query, 200);
  const entries = useMemo(
    () => filterAuditLog(AUDIT_FIXTURE, debounced),
    [debounced],
  );
  return { entries, total: AUDIT_FIXTURE.length, isUsingFixture: true };
}
