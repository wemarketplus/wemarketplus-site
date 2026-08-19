import { useMemo, useState } from 'react';
import { NotebookPen } from 'lucide-react';
import { CL_SALES_ROLES, useRole } from '@/shared/rbac';
import { Button, Card, CardContent, DatePicker, Input, Select } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useListClLeadsQuery,
  useListClLeadNotesQuery,
  useCreateClLeadNoteMutation,
} from '../api/leadsApi';

const PAGE_SIZE = 50;

/**
 * Activity Notes: "general notes not tied to one specific lead" — plus, for the
 * roles that can see the pipeline, the option to attach one to a lead.
 *
 * A LEAD IS OPTIONAL, which is the whole point of the screen and was impossible
 * until `cl_lead_notes.leadId` became nullable: the Save button required a lead,
 * so the one thing the screen is defined as doing could not be done.
 *
 * THE LEAD PICKER IS SKIPPED FOR ROLES THAT CANNOT READ LEADS. `GET /cl/leads` is
 * CL_SALES_ROLES; Nurse and Caregiver are not in it, and they are precisely the
 * roles told to "use Activity Notes as the closest available substitute" for the
 * unbuilt Resident Care Log. Firing that query for them produced a 403, an empty
 * picker, and a Save button that never enabled — the workaround was read-only for
 * the only people it was written for. Skipping the query (rather than widening
 * the leads endpoint) keeps the sales pipeline unreadable to care roles, which is
 * the correct boundary; they simply get the lead-less form.
 */
export function ActivityNotesPage() {
  const { isAny } = useRole();
  const canReadLeads = isAny(CL_SALES_ROLES);
  const { data: leadsData } = useListClLeadsQuery(
    { page: 1, limit: 200 },
    { skip: !canReadLeads },
  );
  const leadOptions = useMemo(
    () =>
      (leadsData?.data ?? []).map((l) => ({
        value: l.id,
        label: `${l.firstName} ${l.lastName ?? ''}`.trim(),
      })),
    [leadsData],
  );
  const leadLabel = useMemo(() => {
    const map = new Map(leadOptions.map((o) => [o.value, o.label]));
    // A note with no lead is a general note, not a broken reference — say so,
    // rather than printing "Unknown lead" over a deliberately empty field.
    return (id: string | null) =>
      id === null ? 'General note' : (map.get(id) ?? 'Unknown lead');
  }, [leadOptions]);

  const { data: notesData, isLoading, error } = useListClLeadNotesQuery({ page: 1, limit: PAGE_SIZE });
  const notes = useMemo(
    () => [...(notesData?.data ?? [])].sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
    [notesData],
  );

  const [createNote, { isLoading: isSaving, error: saveError }] = useCreateClLeadNoteMutation();
  const [leadId, setLeadId] = useState('');
  const [summary, setSummary] = useState('');
  const [nextStep, setNextStep] = useState('');
  const [followUpDate, setFollowUpDate] = useState('');

  // The summary is the note. A lead is an optional subject.
  const canSave = Boolean(summary.trim()) && !isSaving;

  const save = async () => {
    if (!canSave) return;
    await createNote({
      // Omitted when blank: leadId is @IsUUID() on the DTO, so '' would 400.
      ...(leadId ? { leadId } : {}),
      summary: summary.trim(),
      nextStep: nextStep.trim() || undefined,
      followUpDate: followUpDate || undefined,
    }).unwrap();
    setSummary('');
    setNextStep('');
    setFollowUpDate('');
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Activity notes</h1>
        <p className="text-sm text-muted">
          {canReadLeads
            ? 'General notes, and every call, visit and touchpoint you attach to a lead.'
            : 'General notes — wellness checks, incident notes and family updates.'}
        </p>
      </header>

      <Card>
        <CardContent className="space-y-3 pt-6">
          <h2 className="text-sm font-bold text-foreground">Add activity note</h2>
          {saveError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(saveError, 'Failed to save note')}
            </p>
          )}
          {canReadLeads && (
            <Select value={leadId} onChange={(e) => setLeadId(e.target.value)} aria-label="Lead">
              <option value="">No lead — general note</option>
              {leadOptions.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          )}
          <textarea
            className="w-full rounded-md border border-border/10 bg-surface px-3 py-2.5 text-sm text-foreground outline-none focus:border-primary/50"
            rows={3}
            placeholder="What happened? What was discussed?"
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              placeholder="Next step"
              value={nextStep}
              onChange={(e) => setNextStep(e.target.value)}
            />
            <DatePicker
              value={followUpDate}
              onChange={(e) => setFollowUpDate(e.target.value)}
              aria-label="Follow-up date"
            />
          </div>
          <Button onClick={save} disabled={!canSave}>
            Save note
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 pt-6">
          {error ? (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              Failed to load activity notes.
            </p>
          ) : isLoading ? (
            <div className="rounded-[14px] border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : notes.length === 0 ? (
            <EmptyState
              icon={NotebookPen}
              title="No activity yet"
              description="Every note you log appears here in one unified timeline."
            />
          ) : (
            notes.map((n) => (
              <div key={n.id} className="rounded-[14px] border border-border/[0.08] bg-surface px-4 py-3.5">
                <div className="mb-1.5 flex flex-wrap items-center justify-between gap-1.5">
                  <span className="text-[12px] font-bold text-foreground">{leadLabel(n.leadId)}</span>
                  <span className="text-[11px] text-muted-soft">
                    {new Date(n.createdAt).toLocaleString('en-US', {
                      month: 'short',
                      day: 'numeric',
                      hour: 'numeric',
                      minute: '2-digit',
                    })}
                  </span>
                </div>
                <p className="text-[13px] text-muted">{n.summary}</p>
                {n.nextStep && (
                  <p className="mt-1 text-[12px] text-muted-soft">
                    <span className="font-bold text-foreground">Next step:</span> {n.nextStep}
                  </p>
                )}
                {n.followUpDate && (
                  <p className="mt-1 text-[12px] text-muted-soft">
                    <span className="font-bold text-foreground">Follow-up:</span> {n.followUpDate}
                  </p>
                )}
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
