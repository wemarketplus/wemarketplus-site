import { Search } from 'lucide-react';
import { useRole, STAFF_ROLES } from '@/shared/rbac';
import { Input, Select } from '@/shared/ui/core';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { cn } from '@/shared/utils/cn';
import { OUTREACH_VIEWS, VISIT_TYPE_OPTIONS } from '../constants/clOutreachConstants';
import { useOutreach } from '../hooks/useOutreach';
import { useOutreachView } from '../hooks/useOutreachView';
import { useOutreachLog } from '../hooks/useOutreachLog';
import { CheckInList } from '../components/CheckInList';
import { MileageList } from '../components/MileageList';
import { OutreachLogTable } from '../components/OutreachLogTable';
import { VisitFormModal } from '../components/VisitFormModal';

const HEADER_BY_VIEW = {
  checkin: {
    title: 'GPS check-in',
    subtitle: 'Field visits logged with GPS location and timestamp.',
  },
  mileage: {
    title: 'Mileage',
    subtitle: 'Reimbursable miles captured from field visits.',
  },
  log: {
    title: 'Outreach log',
    subtitle: 'Full history of referral-source visits and touchpoints.',
  },
} as const;

// The view tabs (checkin / mileage / log) all read /cl/outreach-visits. The log
// view is the write surface (log/edit/delete a visit); checkin + mileage are
// read-only lenses over the same records.
function ViewTabs({
  view,
  setView,
}: {
  view: ReturnType<typeof useOutreachView>['view'];
  setView: ReturnType<typeof useOutreachView>['setView'];
}) {
  return (
    <nav className="flex flex-wrap gap-1.5">
      {OUTREACH_VIEWS.map((v) => (
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

export function ClOutreachPage() {
  const { view, setView } = useOutreachView();
  const header = HEADER_BY_VIEW[view];

  // Read-only lenses (checkin / mileage) source the same live visits.
  const { checkIns, mileage } = useOutreach();

  // The log view owns full CRUD + server-side search/type filters.
  const log = useOutreachLog();
  const { isAny } = useRole();
  const canEdit = isAny(STAFF_ROLES);

  if (view !== 'log') {
    return (
      <div className="space-y-6">
        <header className="space-y-1">
          <h1 className="font-display text-3xl text-foreground">{header.title}</h1>
          <p className="text-sm text-muted">{header.subtitle}</p>
        </header>
        <ViewTabs view={view} setView={setView} />
        {view === 'checkin' && <CheckInList items={checkIns} />}
        {view === 'mileage' && <MileageList entries={mileage} />}
      </div>
    );
  }

  return (
    <EntityListPage
      title={header.title}
      subtitle={`${log.total} logged visits`}
      addLabel="Log Visit"
      onAdd={canEdit ? log.crud.openCreate : undefined}
      isLoading={log.isLoading}
      error={log.error}
      errorFallback="Failed to load outreach visits"
      filters={
        <div className="space-y-3">
          <ViewTabs view={view} setView={setView} />
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative sm:max-w-sm sm:flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input
                value={log.search}
                onChange={(e) => log.setSearch(e.target.value)}
                placeholder="Search visits…"
                className="pl-9"
                aria-label="Search visits"
              />
            </div>
            <Select
              value={log.type}
              onChange={(e) => log.setType(e.target.value)}
              aria-label="Filter by type"
              className="sm:w-48"
            >
              <option value="">All types</option>
              {VISIT_TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </div>
        </div>
      }
      pagination={
        <EntityPagination
          page={log.page}
          lastPage={log.lastPage}
          isFetching={log.isFetching}
          onPrev={log.prevPage}
          onNext={log.nextPage}
        />
      }
    >
      <OutreachLogTable
        visits={log.rows}
        isMutating={log.isMutating}
        hasFilters={log.hasFilters}
        onEdit={log.crud.openEdit}
        onDelete={log.crud.confirmDelete}
        onAdd={canEdit ? log.crud.openCreate : undefined}
      />
      <VisitFormModal
        open={log.crud.createOpen || log.crud.editing !== null}
        isSaving={log.crud.isSaving}
        editing={log.crud.editing}
        onClose={log.crud.editing ? log.crud.closeEdit : log.crud.closeCreate}
        onSubmit={log.submit}
      />
    </EntityListPage>
  );
}
