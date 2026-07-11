import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClPaidReferralsQuery,
  useCreateClPaidReferralMutation,
  useUpdateClPaidReferralMutation,
  useDeleteClPaidReferralMutation,
} from '../api/clReferralsApi';
import { PAID_REFERRALS_PAGE_SIZE } from '../constants/paidReferralsConstants';
import { toCreatePaidReferral, toUpdatePaidReferral } from '../utils/paidReferralsUtils';
import type { PaidReferralFormValues } from '../schema/paidReferralSchema';
import type { ClPaidReferralRecord } from '../types/clReferralsApiTypes';

// Paid-referral portal CRUD: paginated /cl/paid-referrals with server-side
// search + fee-status + urgency filters, plus the shared create/edit/delete.
export function usePaidReferrals() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [urgency, setUrgency] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status, urgency]);

  const query = useListClPaidReferralsQuery({
    page,
    limit: PAID_REFERRALS_PAGE_SIZE,
    search: debouncedSearch.trim(),
    status,
    urgency,
  });
  const list = usePaginatedList<ClPaidReferralRecord>(query, {
    pageSize: PAID_REFERRALS_PAGE_SIZE,
  });

  const [createReferral, createState] = useCreateClPaidReferralMutation();
  const [updateReferral, updateState] = useUpdateClPaidReferralMutation();
  const [deleteReferral, deleteState] = useDeleteClPaidReferralMutation();

  const crud = useEntityCrud<
    ClPaidReferralRecord,
    ReturnType<typeof toCreatePaidReferral>,
    ReturnType<typeof toUpdatePaidReferral>
  >({
    noun: 'paid referral',
    create: createReferral,
    update: updateReferral,
    remove: deleteReferral,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (r) => r.prospectName,
  });

  const submit = (values: PaidReferralFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdatePaidReferral(values))
      : crud.submitCreate(toCreatePaidReferral(values));

  // Inline fee-status change (Pending -> Paid, etc.).
  const changeFeeStatus = (r: ClPaidReferralRecord, feeStatus: string) =>
    crud.submitUpdate(r.id, { feeStatus: feeStatus as ClPaidReferralRecord['feeStatus'] });

  const hasFilters = Boolean(debouncedSearch.trim() || status || urgency);

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    urgency,
    setUrgency,
    hasFilters,
    isMutating: createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
    changeFeeStatus,
  };
}
