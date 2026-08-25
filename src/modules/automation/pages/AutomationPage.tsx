import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useMemo } from 'react';
import { Plus, RotateCcw } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { FollowUpFormModal } from '../components/FollowUpFormModal';
import { useAutomation } from '../hooks/useAutomation';
import type { FollowUpAutomationRecord } from '../types/automationTypes';

/**
 * Both sides are `YYYY-MM-DD`, so this is a string comparison and not a date
 * one. Parsing to instants would reintroduce the timezone bug the backend
 * avoids by storing the column as a plain date.
 */
const isOverdue = (dueDate: string, today: string): boolean => dueDate < today;

export function AutomationPage() {
  const {
    followUps,
    isLoading,
    isError,
    isFetching,
    refetch,
    prospectOptions,
    prospectsLoading,
    prospectNameById,
    formOpen,
    openForm,
    closeForm,
    submit,
    isSaving,
    cancel,
    cancellingId,
  } = useAutomation();

  // The user's own day boundary, not UTC's — a follow-up due "today" must not
  // read as overdue to someone west of Greenwich at 9am.
  const today = formatDate(new Date(), 'yyyy-MM-dd');

  const columns = useMemo<ReadonlyArray<Column<FollowUpAutomationRecord>>>(
    () => [
      {
        key: 'prospect',
        header: 'Prospect',
        cell: (row) =>
          // A follow-up can outlive the picker's first page (the list is capped
          // at 100 prospects), so an unresolved name is expected rather than an
          // error — the row still has to be readable and cancellable.
          prospectNameById.get(row.prospectId) ?? 'Prospect not in your list',
      },
      {
        key: 'title',
        header: 'What to do',
        cell: (row) => (
          <div className="min-w-0">
            <p className="font-semibold text-foreground">{row.title}</p>
            {row.cadenceNote && (
              <p className="mt-0.5 text-[11px] text-muted-soft">
                {row.cadenceNote}
              </p>
            )}
          </div>
        ),
      },
      {
        key: 'dueDate',
        header: 'Due',
        cell: (row) =>
          isOverdue(row.dueDate, today) ? (
            <Pill tone="r">Overdue · {formatDate(row.dueDate)}</Pill>
          ) : (
            <span className="text-muted">{formatDate(row.dueDate)}</span>
          ),
      },
      {
        key: 'actions',
        header: '',
        headerClassName: 'w-24',
        cell: (row) => (
          <Button
            variant="ghost"
            size="sm"
            disabled={cancellingId === row.id}
            onClick={() => void cancel(row)}
          >
            {cancellingId === row.id ? 'Cancelling…' : 'Cancel'}
          </Button>
        ),
      },
    ],
    [cancel, cancellingId, prospectNameById, today],
  );

  if (isError) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          We could not load your follow-ups right now.{' '}
          <button type="button" onClick={() => refetch()} className="underline">
            Try again
          </button>
          .
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>Automation</h1>
          <p className="text-sm text-muted">
            Standing follow-up reminders on your prospects, so nothing slips.
            Every one of these also appears in Daily tasks on the day it is due.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={() => refetch()} disabled={isFetching}>
            <RotateCcw className="h-4 w-4" />
            {isFetching ? 'Refreshing…' : 'Refresh'}
          </Button>
          <Button onClick={openForm}>
            <Plus className="h-4 w-4" />
            New follow-up
          </Button>
        </div>
      </header>

      <Card>
        <CardContent className="p-0">
          <DataTable<FollowUpAutomationRecord>
            columns={columns}
            rows={followUps}
            rowKey={(row) => row.id}
            empty={
              isLoading
                ? 'Loading your follow-ups…'
                : 'No follow-ups set up yet. Schedule one and it will show up in Daily tasks on the day it is due.'
            }
          />
        </CardContent>
      </Card>

      <FollowUpFormModal
        open={formOpen}
        isSaving={isSaving}
        prospectOptions={prospectOptions}
        prospectsLoading={prospectsLoading}
        onClose={closeForm}
        onSubmit={submit}
      />
    </div>
  );
}
