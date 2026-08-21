import { useMemo, useState } from 'react';
import { useRole, CL_SALES_ROLES } from '@/shared/rbac';
import { SearchInput } from '@/shared/ui/core';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { cn } from '@/shared/utils/cn';
import { usePaidReferrals } from '../hooks/usePaidReferrals';
import { PaidReferralsTable } from '../components/PaidReferralsTable';
import { PaidReferralFormModal } from '../components/PaidReferralFormModal';

// Referral Pipeline (Max tier): the same paid-referral data as the Paid
// Referral Portal, presented as a stage-grouped pipeline — a clickable
// count-per-stage strip filters the table below it.
export function ReferralPipelinePage() {
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
    hasFilters,
    isMutating,
    crud,
    submit,
    changeFeeStatus,
  } = usePaidReferrals();

  const { isAny } = useRole();
  const canEdit = isAny(CL_SALES_ROLES);
  const [stageFilter, setStageFilter] = useState('');

  const stageCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rows) counts.set(r.stage ?? 'New Referral', (counts.get(r.stage ?? 'New Referral') ?? 0) + 1);
    return Array.from(counts.entries());
  }, [rows]);

  const filteredRows = useMemo(
    () => (stageFilter ? rows.filter((r) => (r.stage ?? 'New Referral') === stageFilter) : rows),
    [rows, stageFilter],
  );

  return (
    <EntityListPage
      title="Referral pipeline"
      subtitle={`${total} referrals across every stage`}
      addLabel="Add Referral"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load referral pipeline"
      filters={
        <div className="space-y-3">
          <nav className="flex flex-wrap gap-1.5">
            {stageCounts.map(([stage, count]) => (
              <button
                key={stage}
                type="button"
                onClick={() => setStageFilter((s) => (s === stage ? '' : stage))}
                className={cn(
                  'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
                  stageFilter === stage
                    ? 'border-primary/40 bg-primary/15 text-primary'
                    : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
                )}
              >
                {stage} <span className="opacity-70">({count})</span>
              </button>
            ))}
          </nav>
          <SearchInput
            wrapperClassName="sm:max-w-sm"
            value={search}
            onChange={setSearch}
            placeholder="Search referrals…"
            aria-label="Search referral pipeline"
          />
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
        referrals={filteredRows}
        isMutating={isMutating}
        hasFilters={hasFilters || Boolean(stageFilter)}
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
