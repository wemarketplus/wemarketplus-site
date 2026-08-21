import { useRole, CL_SALES_ROLES } from '@/shared/rbac';
import { Select, SearchInput } from '@/shared/ui/core';
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
  const canEdit = isAny(CL_SALES_ROLES);

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
          <SearchInput
            wrapperClassName="sm:max-w-sm sm:flex-1"
            value={search}
            onChange={setSearch}
            placeholder="Search referrals…"
            aria-label="Search paid referrals"
          />
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
