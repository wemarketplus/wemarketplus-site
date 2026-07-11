import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useCreateClVisitMutation } from '@/modules/cl-outreach';
import {
  useListClReferralSourcesQuery,
  useCreateClReferralSourceMutation,
  useUpdateClReferralSourceMutation,
  useDeleteClReferralSourceMutation,
} from '../api/clReferralsApi';
import { CL_REFERRALS_PAGE_SIZE } from '../constants/clReferralsConstants';
import { toCreateReferral, toUpdateReferral } from '../utils/clReferralsMappers';
import type { ReferralFormValues } from '../schema/clReferralSchema';
import type { ClReferralSourceRecord } from '../types/clReferralsApiTypes';

// ISO (yyyy-mm-dd) for today, local time — used for a logged visit's date and to
// bump the source's lastReferralDate ("Last contact").
function todayIso(): string {
  const now = new Date();
  const tz = now.getTimezoneOffset() * 60_000;
  return new Date(now.getTime() - tz).toISOString().slice(0, 10);
}

// The single hook ClReferralsPage consumes: the paginated /cl/referral-sources
// query, a client-side search + type filter over the page, the shared CRUD
// orchestration, and a "log visit" action that records an outreach visit and
// bumps the source's last-contact date. Mirrors the cl-leads template.
export function useReferralsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  // Any filter change resets to page 1 (the filtered result set is a new list).
  useEffect(() => setPage(1), [debouncedSearch, type]);

  const query = useListClReferralSourcesQuery({
    page,
    limit: CL_REFERRALS_PAGE_SIZE,
    search: debouncedSearch.trim(),
    type,
  });
  const list = usePaginatedList<ClReferralSourceRecord>(query, {
    pageSize: CL_REFERRALS_PAGE_SIZE,
  });

  const [createSource, createState] = useCreateClReferralSourceMutation();
  const [updateSource, updateState] = useUpdateClReferralSourceMutation();
  const [deleteSource, deleteState] = useDeleteClReferralSourceMutation();
  const [createVisit, visitState] = useCreateClVisitMutation();

  const crud = useEntityCrud<
    ClReferralSourceRecord,
    ReturnType<typeof toCreateReferral>,
    ReturnType<typeof toUpdateReferral>
  >({
    noun: 'referral source',
    create: createSource,
    update: updateSource,
    remove: deleteSource,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (r) => r.name,
  });

  const submit = (values: ReferralFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateReferral(values))
      : crud.submitCreate(toCreateReferral(values));

  // Log Visit: records an outreach visit against this source. The backend's
  // outreach-visit create already bumps the source's referralCount and stamps
  // its lastReferralDate (recordReferral), so "Leads sent" / "Last contact"
  // update on the next refetch without a separate PATCH here.
  const logVisit = async (source: ClReferralSourceRecord): Promise<void> => {
    try {
      await createVisit({
        referralSourceId: source.id,
        visitDate: todayIso(),
        contactName: source.name,
        ...(source.organization ? { locationName: source.organization } : {}),
      }).unwrap();
      // The visit lives in a different RTK Query API (cl-outreach), so it can't
      // invalidate this list's cache tag — refetch so the bumped referralCount /
      // lastReferralDate the backend just wrote show immediately.
      void query.refetch();
      toast.success(`Logged a visit to ${source.name}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not log the visit. Please try again.'));
    }
  };

  const hasFilters = Boolean(debouncedSearch.trim() || type);

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    type,
    setType,
    hasFilters,
    isMutating:
      createState.isLoading ||
      updateState.isLoading ||
      deleteState.isLoading ||
      visitState.isLoading,
    crud,
    submit,
    logVisit,
  };
}
