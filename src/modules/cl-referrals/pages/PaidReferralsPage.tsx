import { Search } from 'lucide-react';
import { useRole, STAFF_ROLES } from '@/shared/rbac';
import { Input, Select } from '@/shared/ui/core';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import {
  FEE_STATUS_OPTIONS,
  PR_URGENCY_OPTIONS,
} from '../constants/paidReferralsConstants';
import { usePaidReferrals } from '../hooks/usePaidReferrals';
import { PaidReferralsTable } from '../components/PaidReferralsTable';
import { PaidReferralFormModal } from '../components/PaidReferralFormModal';

export function PaidReferralsPage() {
  const {
    rows,
    total,
    page,
    lastPage,
    isLoading,
    isFetching,
    error,
    prevPage,
    nextPage,
    search,
    setSearch,
    status,
    setStatus,
    urgency,
    setUrgency,
    hasFilters,
    isMutating,
    crud,
    submit,
    changeFeeStatus,
  } = usePaidReferrals();

  const { isAny } = useRole();
  const canEdit = isAny(STAFF_ROLES);

  return (
    <EntityListPage
      title="Paid referral portal"
      subtitle={`${total} placement-agency referrals`}
      addLabel="Add Referral"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load paid referrals"
      filters={
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative sm:max-w-sm sm:flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search referrals…"
              className="pl-9"
              aria-label="Search paid referrals"
            />
          </div>
          <Select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            aria-label="Filter by fee status"
            className="sm:w-44"
          >
            <option value="">All fee statuses</option>
            {FEE_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
          <Select
            value={urgency}
            onChange={(e) => setUrgency(e.target.value)}
            aria-label="Filter by urgency"
            className="sm:w-40"
          >
            <option value="">All urgency</option>
            {PR_URGENCY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
      }
      pagination={
        <EntityPagination
          page={page}
          lastPage={lastPage}
          isFetching={isFetching}
          onPrev={prevPage}
          onNext={nextPage}
        />
      }
    >
      <PaidReferralsTable
        referrals={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onFeeStatusChange={changeFeeStatus}
        onAdd={canEdit ? crud.openCreate : undefined}
      />
      <PaidReferralFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </EntityListPage>
  );
}
