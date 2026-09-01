import { PAGE_TITLE, SECTION_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { HeartPulse } from 'lucide-react';
import { Button, Card, CardContent, DatePicker, Input, Select, Textarea } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { LOOKUP_PAGE_SIZE } from '@/shared/hooks';
import { useListClApartmentsQuery } from '@/modules/cl-operations';
import {
  CL_RESIDENT_NOTE_CATEGORY,
  CL_RESIDENT_NOTE_CATEGORY_LABELS,
  type ClResidentNoteCategory,
} from '../constants/clLeadApiConstants';
import {
  useListClResidentsQuery,
  useCreateClResidentMutation,
  useListClLeadNotesQuery,
  useCreateClLeadNoteMutation,
} from '../api/leadsApi';

const PAGE_SIZE = 50;

/**
 * Resident Care Log — wellness checks, incident notes and family updates tied to
 * a specific resident. Was `comingSoon` on the nav; the blocker was that
 * CommunityLink had no resident record (see `ClResident`, backend). Now live.
 *
 * ENTRIES ARE `cl_lead_notes` ROWS, same table Activity Notes writes to, with
 * `residentId` and `category` set — a Resident Care Log entry is a lead-optional
 * note with a resident as its subject and a category naming which of the three
 * kinds it is, not a second table with a second writer (see ClLeadNote).
 *
 * A RESIDENT MUST EXIST FIRST. The apartment model is "one resident row per
 * apartment, closed not deleted on move-out" (ClResident's own doc comment) —
 * this page's inline "Add resident" form is the minimum needed to create the
 * first one, not a resident/apartment management screen. It is deliberately
 * NOT: an apartment editor, a move-out flow, or a resident directory with
 * search/edit/history — all of that stays out of scope here; apartment
 * inventory itself is managed on the Operations screens.
 */
export function ResidentCareLogPage() {
  const { data: apartmentsData } = useListClApartmentsQuery({ page: 1, limit: LOOKUP_PAGE_SIZE });
  const apartmentOptions = useMemo(
    () => (apartmentsData?.data ?? []).map((a) => ({ value: a.id, label: a.unitNumber })),
    [apartmentsData],
  );

  const { data: residentsData, isLoading: isLoadingResidents } = useListClResidentsQuery({
    page: 1,
    limit: LOOKUP_PAGE_SIZE,
  });
  // Active residents only — a moved-out resident is history, not someone to log
  // a new wellness check against. Filtered client-side: "moveOutDate IS NULL"
  // isn't an equality match, so it isn't one of ClListQueryDto's filter keys.
  const activeResidents = useMemo(
    () => (residentsData?.data ?? []).filter((r) => r.moveOutDate === null),
    [residentsData],
  );
  const residentOptions = useMemo(
    () => activeResidents.map((r) => ({ value: r.id, label: `${r.firstName} ${r.lastName}` })),
    [activeResidents],
  );

  const [residentId, setResidentId] = useState('');

  // --- Add resident (minimal — first/last name + apartment + move-in date) ---
  const [showAddResident, setShowAddResident] = useState(false);
  const [newFirstName, setNewFirstName] = useState('');
  const [newLastName, setNewLastName] = useState('');
  const [newApartmentId, setNewApartmentId] = useState('');
  const [newMoveInDate, setNewMoveInDate] = useState('');
  const [createResident, { isLoading: isCreatingResident, error: createResidentError }] =
    useCreateClResidentMutation();

  const canAddResident =
    Boolean(newFirstName.trim()) &&
    Boolean(newLastName.trim()) &&
    Boolean(newApartmentId) &&
    !isCreatingResident;

  const addResident = async () => {
    if (!canAddResident) return;
    const resident = await createResident({
      apartmentId: newApartmentId,
      firstName: newFirstName.trim(),
      lastName: newLastName.trim(),
      moveInDate: newMoveInDate || undefined,
    }).unwrap();
    setNewFirstName('');
    setNewLastName('');
    setNewApartmentId('');
    setNewMoveInDate('');
    setShowAddResident(false);
    setResidentId(resident.id);
  };

  // --- Log a care entry against the selected resident ---
  const [category, setCategory] = useState<ClResidentNoteCategory | ''>('');
  const [summary, setSummary] = useState('');
  const [nextStep, setNextStep] = useState('');
  const [followUpDate, setFollowUpDate] = useState('');
  const [createNote, { isLoading: isSaving, error: saveError }] = useCreateClLeadNoteMutation();

  const canSave = Boolean(residentId) && Boolean(summary.trim()) && !isSaving;

  const save = async () => {
    if (!canSave) return;
    await createNote({
      residentId,
      summary: summary.trim(),
      // Omitted when blank: category is @IsEnum() on the DTO, so '' would 400.
      ...(category ? { category } : {}),
      nextStep: nextStep.trim() || undefined,
      followUpDate: followUpDate || undefined,
    }).unwrap();
    setCategory('');
    setSummary('');
    setNextStep('');
    setFollowUpDate('');
  };

  // Entries for the selected resident only — this list is deliberately not the
  // whole tenant's care log, it's one resident's chart.
  const { data: entriesData, isLoading: isLoadingEntries, error: entriesError } = useListClLeadNotesQuery(
    { page: 1, limit: PAGE_SIZE, residentId },
    { skip: !residentId },
  );
  const entries = useMemo(
    () => [...(entriesData?.data ?? [])].sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
    [entriesData],
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Resident care log</h1>
        <p className="text-sm text-muted">
          Wellness checks, incident notes and family updates tied to a specific resident.
        </p>
      </header>

      <Card>
        <CardContent className="space-y-3 pt-6">
          <h2 className={SECTION_TITLE}>Resident</h2>
          {isLoadingResidents ? (
            <div className="rounded-card border border-border/[0.09] bg-surface p-6 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : residentOptions.length === 0 && !showAddResident ? (
            <EmptyState
              icon={HeartPulse}
              title="No residents yet"
              description="Add the first resident to start logging care entries."
              actionLabel="Add resident"
              onAction={() => setShowAddResident(true)}
            />
          ) : (
            <>
              <Select value={residentId} onChange={(e) => setResidentId(e.target.value)} aria-label="Resident">
                <option value="">Select a resident…</option>
                {residentOptions.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
              {!showAddResident && (
                <Button variant="ghost" onClick={() => setShowAddResident(true)}>
                  + Add resident
                </Button>
              )}
            </>
          )}

          {showAddResident && (
            <div className="space-y-3 rounded-card border border-border/[0.08] bg-surface px-4 py-3.5">
              {createResidentError && (
                <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
                  {extractApiErrorMessage(createResidentError, 'Failed to add resident')}
                </p>
              )}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Input
                  placeholder="First name"
                  value={newFirstName}
                  onChange={(e) => setNewFirstName(e.target.value)}
                />
                <Input
                  placeholder="Last name"
                  value={newLastName}
                  onChange={(e) => setNewLastName(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Select
                  value={newApartmentId}
                  onChange={(e) => setNewApartmentId(e.target.value)}
                  aria-label="Apartment"
                >
                  <option value="">Select a unit…</option>
                  {apartmentOptions.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </Select>
                <DatePicker
                  value={newMoveInDate}
                  onChange={(e) => setNewMoveInDate(e.target.value)}
                  aria-label="Move-in date"
                />
              </div>
              <div className="flex gap-2">
                <Button onClick={addResident} disabled={!canAddResident}>
                  Save resident
                </Button>
                <Button variant="ghost" onClick={() => setShowAddResident(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 pt-6">
          <h2 className={SECTION_TITLE}>Log a care entry</h2>
          {saveError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(saveError, 'Failed to save entry')}
            </p>
          )}
          {!residentId && (
            <p className="text-[13px] text-muted-soft">Select a resident above to log an entry.</p>
          )}
          <Select
            value={category}
            onChange={(e) => setCategory(e.target.value as ClResidentNoteCategory | '')}
            aria-label="Category"
            disabled={!residentId}
          >
            <option value="">Select a category…</option>
            {Object.values(CL_RESIDENT_NOTE_CATEGORY).map((c) => (
              <option key={c} value={c}>
                {CL_RESIDENT_NOTE_CATEGORY_LABELS[c]}
              </option>
            ))}
          </Select>
          <Textarea
            rows={3}
            placeholder="What happened? What was observed or discussed?"
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            disabled={!residentId}
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input
              placeholder="Next step"
              value={nextStep}
              onChange={(e) => setNextStep(e.target.value)}
              disabled={!residentId}
            />
            <DatePicker
              value={followUpDate}
              onChange={(e) => setFollowUpDate(e.target.value)}
              aria-label="Follow-up date"
              disabled={!residentId}
            />
          </div>
          <Button onClick={save} disabled={!canSave}>
            Save entry
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 pt-6">
          {!residentId ? (
            <EmptyState
              icon={HeartPulse}
              title="No resident selected"
              description="Select a resident above to see their care log."
            />
          ) : entriesError ? (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              Failed to load the care log.
            </p>
          ) : isLoadingEntries ? (
            <div className="rounded-card border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : entries.length === 0 ? (
            <EmptyState
              icon={HeartPulse}
              title="No entries yet"
              description="Every wellness check, incident note and family update you log for this resident appears here."
            />
          ) : (
            entries.map((n) => (
              <div key={n.id} className="rounded-card border border-border/[0.08] bg-surface px-4 py-3.5">
                <div className="mb-1.5 flex flex-wrap items-center justify-between gap-1.5">
                  <span className="text-[12px] font-bold text-foreground">
                    {n.category ? CL_RESIDENT_NOTE_CATEGORY_LABELS[n.category] : 'Note'}
                  </span>
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
