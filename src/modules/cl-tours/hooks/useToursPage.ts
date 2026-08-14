import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import { useListClLeadsQuery } from '@/modules/cl-leads';
import { useListAssignableStaffQuery } from '@/modules/users';
import {
  useListClToursQuery,
  useCreateClTourMutation,
  useUpdateClTourMutation,
  useDeleteClTourMutation,
} from '../api/clToursApi';
import { CL_TOURS_PAGE_SIZE } from '../constants/clToursConstants';
import { localToIso, toCreateTour, toUpdateTour } from '../utils/clToursUtils';
import type { TourFormValues } from '../schema/clTourSchema';
import type { ClTourRecord } from '../types/clToursApiTypes';

// Tour scheduler page: paginated /cl/tours with server-side search + status
// filter, the shared CRUD orchestration, an inline status change, and a lead
// lookup (id -> name) so rows show the prospect rather than a raw UUID.
export function useToursPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListClToursQuery({
    page,
    limit: CL_TOURS_PAGE_SIZE,
    search: debouncedSearch.trim(),
    status,
  });
  const list = usePaginatedList<ClTourRecord>(query, { pageSize: CL_TOURS_PAGE_SIZE });

  // Leads for the picker + id->name resolution on rows.
  const { data: leadsData } = useListClLeadsQuery({ page: 1, limit: 100 });
  const leadOptions = useMemo(
    () =>
      (leadsData?.data ?? []).map((l) => ({
        value: l.id,
        label: [l.firstName, l.lastName].filter(Boolean).join(' ') || 'Lead',
      })),
    [leadsData],
  );
  const leadName = useMemo(() => {
    const map = new Map(leadOptions.map((o) => [o.value, o.label]));
    return (id: string | null) => (id ? (map.get(id) ?? 'Lead') : '—');
  }, [leadOptions]);

  /**
   * Tenant staff for the "who is giving the tour" picker, and the id -> name table
   * the Guide column reads.
   *
   * `/users/assignable`, NOT the shared `useUserLookup`. That hook reads
   * `GET /users`, which is @Roles(Admin, Owner, Manager) — so for a Sales Marketer,
   * the persona whose guide says to "pick … which staff member is giving the tour",
   * it 403s and the picker renders empty. `/users/assignable` is the id+name
   * projection that exists for exactly this (see StaffOptionDto).
   *
   * Fetched unconditionally rather than gated on the modal being open, because the
   * TABLE needs the names on first paint — a Guide column showing a uuid until you
   * happen to open a form is worse than one extra request.
   */
  const { data: staff, isLoading: isStaffLoading } =
    useListAssignableStaffQuery();
  const guideOptions = useMemo(
    () =>
      isStaffLoading
        ? undefined
        : (staff ?? []).map((s) => ({ value: s.id, label: s.name })),
    [staff, isStaffLoading],
  );
  // An unresolved id yields 'Unassigned', never the uuid: a uuid on screen looks
  // like data while telling the user nothing (see useRecordLookups).
  const guideName = useMemo(() => {
    const byId = new Map((staff ?? []).map((s) => [s.id, s.name]));
    return (id: string | null) => (id ? (byId.get(id) ?? 'Unassigned') : '—');
  }, [staff]);

  const [createTour, createState] = useCreateClTourMutation();
  const [updateTour, updateState] = useUpdateClTourMutation();
  const [deleteTour, deleteState] = useDeleteClTourMutation();

  // Wrap create/update so the modal's TourFormValues are converted (and the
  // datetime parsed) before hitting the shared useEntityCrud mutation shape.
  const crud = useEntityCrud<ClTourRecord, TourFormValues, TourFormValues>({
    noun: 'tour',
    create: (v) => {
      const iso = localToIso(v.scheduledAt);
      if (!iso) throw new Error('Bad date');
      return createTour(toCreateTour(v, iso));
    },
    update: ({ id, patch }) => {
      const iso = localToIso(patch.scheduledAt);
      if (!iso) throw new Error('Bad date');
      return updateTour({ id, patch: toUpdateTour(patch, iso) });
    },
    remove: deleteTour,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (t) => `${leadName(t.leadId)} tour`,
  });

  const submit = (values: TourFormValues) =>
    crud.editing ? crud.submitUpdate(crud.editing.id, values) : crud.submitCreate(values);

  const changeStatus = async (tour: ClTourRecord, statusValue: string) => {
    try {
      await updateTour({
        id: tour.id,
        patch: { status: statusValue as ClTourRecord['status'] },
      }).unwrap();
      toast.success('Tour updated');
    } catch {
      toast.error('Could not update the tour.');
    }
  };

  /**
   * The guide's Confirm action: stamp `confirmedAt` now, or clear it to undo.
   *
   * A targeted PATCH of the one field rather than a round-trip through the edit
   * form — confirming is a single click at the end of a phone call, and sending
   * the whole record back would also re-send `scheduledAt`, which is how an
   * unrelated field gets quietly rewritten by a button that claims to do one
   * thing.
   */
  const toggleConfirmed = async (tour: ClTourRecord) => {
    const confirming = tour.confirmedAt === null;
    try {
      await updateTour({
        id: tour.id,
        patch: { confirmedAt: confirming ? new Date().toISOString() : null },
      }).unwrap();
      toast.success(confirming ? 'Tour confirmed' : 'Confirmation removed');
    } catch {
      toast.error('Could not update the confirmation.');
    }
  };

  const hasFilters = Boolean(debouncedSearch.trim() || status);

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    hasFilters,
    leadName,
    leadOptions,
    guideName,
    guideOptions,
    isMutating:
      createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
    changeStatus,
    toggleConfirmed,
  };
}
