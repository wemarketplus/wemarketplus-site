import { useAppDispatch } from '@/app/hooks';
import type { LeadStatus } from '@/shared/types';
import { updateLeadStatus } from '../store/leadsSlice';

export function useLeadsTable() {
  const dispatch = useAppDispatch();
  const onStatusChange = (id: string, status: LeadStatus) =>
    dispatch(updateLeadStatus({ id, status }));
  return { onStatusChange };
}
