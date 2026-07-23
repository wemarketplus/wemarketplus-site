import { useMemo, useState } from 'react';
import { NotebookPen } from 'lucide-react';
import { Button, Card, CardContent, Input, Select } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useListClLeadsQuery,
  useListClLeadNotesQuery,
  useCreateClLeadNoteMutation,
} from '../api/leadsApi';

const PAGE_SIZE = 50;

// Activity Notes (Max tier): a cross-lead timeline — log a note against any
// lead, then see every note across the pipeline in one place, newest first.
export function ActivityNotesPage() {
  const { data: leadsData } = useListClLeadsQuery({ page: 1, limit: 200 });
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
    return (id: string) => map.get(id) ?? 'Unknown lead';
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

  const canSave = Boolean(leadId && summary.trim()) && !isSaving;

  const save = async () => {
    if (!canSave) return;
    await createNote({
      leadId,
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
        <p className="text-sm text-muted">Every call, visit, and touchpoint — logged against a lead.</p>
      </header>

      <Card>
        <CardContent className="space-y-3 pt-6">
          <h2 className="text-sm font-bold text-foreground">Add activity note</h2>
          {saveError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(saveError, 'Failed to save note')}
            </p>
          )}
          <Select value={leadId} onChange={(e) => setLeadId(e.target.value)} aria-label="Lead">
            <option value="">Select a lead…</option>
            {leadOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
          <textarea
            className="w-full rounded-md border border-white/10 bg-surface px-3 py-2.5 text-sm text-foreground outline-none focus:border-primary/50"
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
            <Input
              type="date"
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
            <div className="rounded-[12px] border border-white/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
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
              <div key={n.id} className="rounded-[12px] border border-white/[0.08] bg-surface px-4 py-3.5">
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
