import { useAppDispatch, useAppSelector } from '@/app/hooks';
import type { LeadStatus } from '@/shared/types';
import { openAddLead, setLeadStatusFilter } from '../store/leadsSlice';

export function useLeadsPage() {
  const dispatch = useAppDispatch();
  const status = useAppSelector((s) => s.clLeads.statusFilter);
  const setFilter = (s: LeadStatus | 'all') => dispatch(setLeadStatusFilter(s));
  const openModal = () => dispatch(openAddLead());
  return { status, setFilter, openModal };
}
