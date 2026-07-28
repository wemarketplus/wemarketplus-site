import { Search } from 'lucide-react';
import { useRole, CL_FINANCIAL_ROLES } from '@/shared/rbac';
import { Input, Select } from '@/shared/ui/core';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { cn } from '@/shared/utils/cn';
import {
  FINANCIAL_VIEWS,
  CONCESSION_STATUS_OPTIONS,
  LEAKAGE_STATUS_OPTIONS,
} from '../constants/clFinancialConstants';
import { useFinancialView } from '../hooks/useFinancialView';
import { useRevenueLedger } from '../hooks/useRevenueLedger';
import { useConcessions } from '../hooks/useConcessions';
import { useCompetitors } from '../hooks/useCompetitors';
import { useLocPricing } from '../hooks/useLocPricing';
import { useLeakage } from '../hooks/useLeakage';
import { RevenueTable } from '../components/RevenueTable';
import { RevenueFormModal } from '../components/RevenueFormModal';
import { ConcessionsTable } from '../components/ConcessionsTable';
import { ConcessionFormModal } from '../components/ConcessionFormModal';
import { CompetitorsTable } from '../components/CompetitorsTable';
import { CompetitorFormModal } from '../components/CompetitorFormModal';
import { LocTable } from '../components/LocTable';
import { LocFormModal } from '../components/LocFormModal';
import { LocQuickCalculator } from '../components/LocQuickCalculator';
import { LeakageTable } from '../components/LeakageTable';
import { LeakageFormModal } from '../components/LeakageFormModal';

const HEADER = {
  ledger: { title: 'Financial ledger', subtitle: 'Revenue entries against budget.', noun: 'entries', add: 'Add Entry' },
  leakage: { title: 'Revenue leakage', subtitle: 'Missed billables, concessions, and downgrades.', noun: 'items', add: 'Add Leakage Item' },
  concessions: { title: 'Concession approvals', subtitle: 'Review and approve rent concessions.', noun: 'concessions', add: 'Add Concession' },
  competitors: { title: 'Competitor intel', subtitle: 'Nearby community rates and occupancy.', noun: 'competitors', add: 'Add Competitor' },
  loc: { title: 'LOC calculator', subtitle: 'Level-of-care add-on pricing.', noun: 'levels', add: 'Add Level' },
} as const;

function ViewTabs({
  view,
  setView,
}: {
  view: ReturnType<typeof useFinancialView>['view'];
  setView: ReturnType<typeof useFinancialView>['setView'];
}) {
  return (
    <nav className="flex flex-wrap gap-1.5">
      {FINANCIAL_VIEWS.map((v) => (
        <button
          key={v.value}
          type="button"
          onClick={() => setView(v.value)}
          className={cn(
            'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
            view === v.value
              ? 'border-primary/40 bg-primary/15 text-primary'
              : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
          )}
        >
          {v.label}
        </button>
      ))}
    </nav>
  );
}

export function ClFinancialPage() {
  const { view, setView } = useFinancialView();
  const { isAny } = useRole();
  const canEdit = isAny(CL_FINANCIAL_ROLES);

  const revenue = useRevenueLedger();
  const concessions = useConcessions();
  const competitors = useCompetitors();
  const loc = useLocPricing();
  const leakage = useLeakage();

  // The active resource controller for the current view (all share the same
  // list/crud/pagination surface via useEntityCrud + usePaginatedList).
  const active =
    view === 'concessions'
      ? concessions
      : view === 'competitors'
        ? competitors
        : view === 'loc'
          ? loc
          : view === 'leakage'
            ? leakage
            : revenue;
  const header = HEADER[view];

  return (
    <EntityListPage
      title={header.title}
      subtitle={`${active.total} ${header.noun}`}
      addLabel={header.add}
      onAdd={canEdit ? active.crud.openCreate : undefined}
      isLoading={active.isLoading}
      error={active.error}
      errorFallback="Failed to load financial data"
      filters={
        <div className="space-y-3">
          <ViewTabs view={view} setView={setView} />
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative sm:max-w-sm sm:flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input
                value={active.search}
                onChange={(e) => active.setSearch(e.target.value)}
                placeholder="Search…"
                className="pl-9"
                aria-label="Search"
              />
            </div>
            {view === 'concessions' && (
              <Select
                value={concessions.status}
                onChange={(e) => concessions.setStatus(e.target.value)}
                aria-label="Filter by status"
                className="sm:w-48"
              >
                <option value="">All statuses</option>
                {CONCESSION_STATUS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            )}
            {view === 'leakage' && (
              <Select
                value={leakage.status}
                onChange={(e) => leakage.setStatus(e.target.value)}
                aria-label="Filter by status"
                className="sm:w-48"
              >
                <option value="">All statuses</option>
                {LEAKAGE_STATUS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            )}
          </div>
        </div>
      }
      pagination={
        <EntityPagination
          page={active.page}
          lastPage={active.lastPage}
          isFetching={active.isFetching}
          onPrev={active.prevPage}
          onNext={active.nextPage}
        />
      }
    >
      {view === 'ledger' && (
        <>
          <RevenueTable
            entries={revenue.rows}
            leakage={false}
            isMutating={revenue.isMutating}
            hasFilters={revenue.hasFilters}
            onEdit={revenue.crud.openEdit}
            onDelete={revenue.crud.confirmDelete}
            onAdd={canEdit ? revenue.crud.openCreate : undefined}
          />
          <RevenueFormModal
            open={revenue.crud.createOpen || revenue.crud.editing !== null}
            isSaving={revenue.crud.isSaving}
            editing={revenue.crud.editing}
            onClose={revenue.crud.editing ? revenue.crud.closeEdit : revenue.crud.closeCreate}
            onSubmit={revenue.submit}
          />
        </>
      )}

      {view === 'leakage' && (
        <>
          <LeakageTable
            items={leakage.rows}
            isMutating={leakage.isMutating}
            hasFilters={leakage.hasFilters}
            onEdit={leakage.crud.openEdit}
            onDelete={leakage.crud.confirmDelete}
            onResolve={leakage.resolve}
            onAdd={canEdit ? leakage.crud.openCreate : undefined}
          />
          <LeakageFormModal
            open={leakage.crud.createOpen || leakage.crud.editing !== null}
            isSaving={leakage.crud.isSaving}
            editing={leakage.crud.editing}
            onClose={leakage.crud.editing ? leakage.crud.closeEdit : leakage.crud.closeCreate}
            onSubmit={leakage.submit}
          />
        </>
      )}

      {view === 'concessions' && (
        <>
          <ConcessionsTable
            concessions={concessions.rows}
            isMutating={concessions.isMutating}
            hasFilters={concessions.hasFilters}
            onEdit={concessions.crud.openEdit}
            onDelete={concessions.crud.confirmDelete}
            onDecide={concessions.decide}
            onAdd={canEdit ? concessions.crud.openCreate : undefined}
          />
          <ConcessionFormModal
            open={concessions.crud.createOpen || concessions.crud.editing !== null}
            isSaving={concessions.crud.isSaving}
            editing={concessions.crud.editing}
            onClose={concessions.crud.editing ? concessions.crud.closeEdit : concessions.crud.closeCreate}
            onSubmit={concessions.submit}
          />
        </>
      )}

      {view === 'competitors' && (
        <>
          <CompetitorsTable
            competitors={competitors.rows}
            isMutating={competitors.isMutating}
            hasFilters={competitors.hasFilters}
            onEdit={competitors.crud.openEdit}
            onDelete={competitors.crud.confirmDelete}
            onAdd={canEdit ? competitors.crud.openCreate : undefined}
          />
          <CompetitorFormModal
            open={competitors.crud.createOpen || competitors.crud.editing !== null}
            isSaving={competitors.crud.isSaving}
            editing={competitors.crud.editing}
            onClose={competitors.crud.editing ? competitors.crud.closeEdit : competitors.crud.closeCreate}
            onSubmit={competitors.submit}
          />
        </>
      )}

      {view === 'loc' && (
        <>
          <LocQuickCalculator levels={loc.rows} />
          <LocTable
            levels={loc.rows}
            isMutating={loc.isMutating}
            hasFilters={loc.hasFilters}
            onEdit={loc.crud.openEdit}
            onDelete={loc.crud.confirmDelete}
            onAdd={canEdit ? loc.crud.openCreate : undefined}
          />
          <LocFormModal
            open={loc.crud.createOpen || loc.crud.editing !== null}
            isSaving={loc.crud.isSaving}
            editing={loc.crud.editing}
            onClose={loc.crud.editing ? loc.crud.closeEdit : loc.crud.closeCreate}
            onSubmit={loc.submit}
          />
        </>
      )}
    </EntityListPage>
  );
}
