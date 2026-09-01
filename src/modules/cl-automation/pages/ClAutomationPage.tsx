import { useState } from 'react';
import { Plus, Workflow } from 'lucide-react';
import { toast } from 'sonner';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { Button, Switch } from '@/shared/ui/core';
import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState, confirm } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useCreateSequenceMutation,
  useDeleteSequenceMutation,
  useGetSequenceQuery,
  useListEnrollmentsQuery,
  useListSequencesQuery,
  useUpdateSequenceMutation,
} from '../api/clAutomationApi';
import { SequenceFormModal } from '../components/SequenceFormModal';
import {
  CL_SEQUENCES_PAGE_SIZE,
  ENROLLMENT_STATUS_LABELS,
  ENROLLMENT_STATUS_PILL,
  SEQUENCE_TRIGGER_LABELS,
} from '../constants/clAutomationConstants';
import type {
  CreateSequenceRequest,
  EnrollmentRecord,
  SequenceRecord,
} from '../types/clAutomationTypes';

/**
 * Follow-up sequences — the multi-step, multi-day campaigns.
 *
 * ── HOW THIS DIFFERS FROM THE OTHER THREE THINGS CALLED "FOLLOW-UP" ───────────
 * The product already has: Tasks (a to-do somebody typed), Daily tasks (today's
 * due work, computed when the screen loads), and HospiceLink's Automation screen (a
 * single standing reminder on one prospect). None of them is a sequence — none can
 * express "three touches over two weeks, advancing on its own, stopping if the
 * family comes back". That is what this screen is for, and the copy below says so,
 * because a fourth follow-up surface with no stated difference is how a user ends up
 * unable to find the one they were told about.
 *
 * ── WHY WRITES ARE ADMIN-ONLY IN THE UI ───────────────────────────────────────
 * `ADMIN_ONLY` mirrors the controller's `@Roles(Admin, Owner, Manager)` on create,
 * update and delete. A sequence acts for the whole team over days — one person
 * editing it changes what every rep's task list fills with tomorrow. Reading stays
 * open to the sales group so a rep can see WHY a task appeared, which is the
 * question an unexplained automated task always raises.
 */
export function ClAutomationPage() {
  const { isAny } = useRole();
  const canEdit = isAny(ADMIN_ONLY);

  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  const { data, isLoading } = useListSequencesQuery({
    page,
    limit: CL_SEQUENCES_PAGE_SIZE,
  });
  // Only fetched while the edit modal is open: the list response deliberately omits
  // steps, so the form needs the single read to seed itself.
  const { data: editing } = useGetSequenceQuery(editingId ?? '', {
    skip: !editingId,
  });
  const { data: runs } = useListEnrollmentsQuery({ page: 1, limit: 25 });

  const [createSequence, createState] = useCreateSequenceMutation();
  const [updateSequence, updateState] = useUpdateSequenceMutation();
  const [deleteSequence] = useDeleteSequenceMutation();

  const rows = data?.data ?? [];
  const isSaving = createState.isLoading || updateState.isLoading;

  const submitCreate = async (values: CreateSequenceRequest) => {
    try {
      await createSequence(values).unwrap();
      toast.success('Sequence created.');
      setCreating(false);
    } catch (error) {
      toast.error(extractApiErrorMessage(error, 'Could not create that sequence.'));
    }
  };

  const submitUpdate = async (values: CreateSequenceRequest) => {
    if (!editingId) return;
    try {
      await updateSequence({ id: editingId, patch: values }).unwrap();
      toast.success('Sequence updated.');
      setEditingId(null);
    } catch (error) {
      toast.error(extractApiErrorMessage(error, 'Could not update that sequence.'));
    }
  };

  /**
   * The active switch, with a confirmation when runs are in flight.
   *
   * Switching a sequence off CANCELS the campaigns already going — the server does
   * that deliberately, because a run left active would keep firing touches from
   * something somebody had just stopped. That is a consequence worth naming before
   * it happens rather than explaining afterwards, so the confirm states the count.
   */
  const toggleActive = async (sequence: SequenceRecord) => {
    if (sequence.isActive) {
      const ok = await confirm({
        title: `Switch off “${sequence.name}”?`,
        body: 'Any leads part-way through it will stop receiving the remaining touches. Their finished touches are kept.',
        confirmLabel: 'Switch off',
      });
      if (!ok) return;
    }
    try {
      await updateSequence({
        id: sequence.id,
        patch: { isActive: !sequence.isActive },
      }).unwrap();
    } catch (error) {
      toast.error(extractApiErrorMessage(error, 'Could not change that sequence.'));
    }
  };

  const remove = async (sequence: SequenceRecord) => {
    const ok = await confirm({
      title: `Delete “${sequence.name}”?`,
      body: 'Its history goes with it, and any leads part-way through will stop.',
      confirmLabel: 'Delete',
      destructive: true,
    });
    if (!ok) return;
    try {
      await deleteSequence(sequence.id).unwrap();
      toast.success('Sequence deleted.');
    } catch (error) {
      toast.error(extractApiErrorMessage(error, 'Could not delete that sequence.'));
    }
  };

  const columns: ReadonlyArray<Column<SequenceRecord>> = [
    {
      key: 'name',
      header: 'Sequence',
      cell: (s) => (
        <div>
          <p className="font-bold text-foreground">{s.name}</p>
          {s.description && (
            <p className="text-[11px] text-muted-soft">{s.description}</p>
          )}
        </div>
      ),
    },
    {
      key: 'trigger',
      header: 'Starts when',
      cell: (s) => SEQUENCE_TRIGGER_LABELS[s.trigger],
    },
    {
      key: 'active',
      header: 'On',
      cell: (s) =>
        canEdit ? (
          <Switch
            checked={s.isActive}
            onCheckedChange={() => void toggleActive(s)}
            aria-label={`Switch ${s.name} ${s.isActive ? 'off' : 'on'}`}
          />
        ) : (
          <Pill tone={s.isActive ? 'g' : 'y'}>{s.isActive ? 'On' : 'Off'}</Pill>
        ),
    },
    { key: 'created', header: 'Created', cell: (s) => formatDate(s.createdAt) },
    ...(canEdit
      ? [
          {
            key: 'actions',
            header: '',
            headerClassName: 'w-20',
            className: 'text-right',
            cell: (s: SequenceRecord) => (
              <EntityRowActions
                onEdit={() => setEditingId(s.id)}
                onDelete={() => void remove(s)}
                editLabel={`Edit ${s.name}`}
                deleteLabel={`Delete ${s.name}`}
              />
            ),
          } as Column<SequenceRecord>,
        ]
      : []),
  ];

  const runColumns: ReadonlyArray<Column<EnrollmentRecord>> = [
    {
      key: 'status',
      header: 'Status',
      cell: (r) => (
        <Pill tone={ENROLLMENT_STATUS_PILL[r.status]}>
          {ENROLLMENT_STATUS_LABELS[r.status]}
        </Pill>
      ),
    },
    {
      key: 'step',
      header: 'On step',
      // 1-based for a reader; the column is 0-based because it is an index.
      cell: (r) => `Step ${r.currentStepIndex + 1}`,
    },
    {
      key: 'next',
      header: 'Next touch',
      cell: (r) => (r.nextFireAt ? formatDate(r.nextFireAt) : '—'),
    },
    {
      key: 'why',
      header: 'Why it stopped',
      // The reason is stored rather than derived because "the lead came back" and
      // "somebody switched the sequence off" leave the same status behind, and the
      // person asking why a family stopped hearing from them needs the difference.
      cell: (r) => r.stoppedReason ?? '—',
    },
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>Follow-up sequences</h1>
          <p className="max-w-2xl text-sm text-muted">
            A set of touches that runs itself over days — starting when a lead
            reaches a stage, advancing on its own, and stopping if the family comes
            back. Distinct from Tasks, which you create one at a time, and Daily
            tasks, which is today’s due work.
          </p>
        </div>
        {canEdit && (
          <Button onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" /> New sequence
          </Button>
        )}
      </header>

      {rows.length === 0 && !isLoading ? (
        <EmptyState
          icon={Workflow}
          title="No sequences yet"
          description="Build one to keep following up automatically after a lead is lost or goes quiet, instead of relying on somebody remembering."
          {...(canEdit
            ? {
                actionLabel: 'New sequence',
                onAction: () => setCreating(true),
              }
            : {})}
        />
      ) : (
        <DataTable columns={columns} rows={rows} rowKey={(s) => s.id} />
      )}

      {(runs?.data.length ?? 0) > 0 && (
        <section className="space-y-3">
          <h2 className="text-[13px] font-semibold uppercase tracking-label text-muted">
            Recent runs
          </h2>
          <DataTable
            columns={runColumns}
            rows={runs?.data ?? []}
            rowKey={(r) => r.id}
          />
        </section>
      )}

      {data && data.total > CL_SEQUENCES_PAGE_SIZE && (
        <div className="flex items-center justify-end gap-2">
          <Button
            variant="secondary"
            disabled={page === 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </Button>
          <Button
            variant="secondary"
            disabled={page * CL_SEQUENCES_PAGE_SIZE >= data.total}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      )}

      {creating && (
        <SequenceFormModal
          isSaving={isSaving}
          onClose={() => setCreating(false)}
          onSubmit={submitCreate}
        />
      )}
      {/* Mounted only once the single read has landed, so the form seeds from real
          steps rather than opening empty and filling in underneath the user. */}
      {editingId && editing && (
        <SequenceFormModal
          sequence={editing}
          isSaving={isSaving}
          onClose={() => setEditingId(null)}
          onSubmit={submitUpdate}
        />
      )}
    </div>
  );
}
