import { MessagesSquare, Plus, TriangleAlert } from 'lucide-react';
import { LogInteractionModal } from '@/modules/activity/components/LogInteractionModal';
import {
  ACTIVITY_TYPE_LABELS,
  ActivityType,
  FAMILY_CONTACT_ACTIVITY_OPTIONS,
} from '@/shared/constants/activityTypeConstants';
import { Button, Card, CardContent, Label, Select } from '@/shared/ui/core';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { useFamilyCommunication } from '../hooks/useFamilyCommunication';
import { PAGE_TITLE } from '@/shared/ui/core/typography';

/**
 * Family Communication — the log of every conversation held with a patient's
 * family, by phone, text or in person.
 *
 * REPLACES a telehealth-sessions table that used to render here. `/clinical/family`
 * showed "Family telehealth visits" (scheduled video calls), which is a different
 * thing from what the nurse guide asks for on this screen: "Every time you speak
 * with a patient's family — by phone, text, or in person — log it here. This is
 * required for compliance, so don't skip it even for a quick call." Video visits are
 * the Telehealth & patient portal item, which the guide lists as coming soon.
 *
 * Built on the notes module rather than a new one — see useFamilyCommunication for
 * why a note IS a logged family conversation.
 */
export function FamilyCommunicationPage() {
  const {
    entries,
    isLoading,
    isError,
    refetch,
    patients,
    patientId,
    setPatientId,
    logOpen,
    openLog,
    closeLog,
    isSaving,
    submit,
  } = useFamilyCommunication();

  const channel = (type: string | null, other: string | null) =>
    type
      ? (ACTIVITY_TYPE_LABELS[type as keyof typeof ACTIVITY_TYPE_LABELS] ?? type)
      : (other ?? 'Contact');

  return (
    <div className="space-y-6">
      <header className="flex items-start gap-4">
        <div className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
          <MessagesSquare className="h-5 w-5" />
        </div>
        <div>
          <h1 className={PAGE_TITLE}>
            Family communication
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">
            Every conversation with a patient&apos;s family — phone, text or in
            person. This log is a compliance record, so log even a quick call.
          </p>
        </div>
      </header>

      {/* Pick the patient first: the log entry is a note ABOUT a patient, and the
          backend rejects one with no target. Clinical roles see every patient in the
          tenant (names only — GET /prospects/patient-directory); marketing roles see
          the whole pipeline. It is deliberately NOT scoped to the patients the caller
          has visits with: the rule this screen serves is "log every call", and a
          nurse covering a shift or with no visit booked yet must still be able to
          file one. See useNoteLookups. */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 px-6 py-5">
          <div className="min-w-[240px] flex-1">
            <Label htmlFor="fc-patient">Patient</Label>
            <Select
              id="fc-patient"
              value={patientId}
              disabled={patients === undefined}
              onChange={(e) => setPatientId(e.target.value)}
            >
              {/* The empty case is now genuinely "this tenant has no patients on
                  file", not "none are assigned to you" — so it names the person who
                  can fix it instead of leaving a clinician stuck at a disabled
                  button with a compliance record to file. */}
              <option value="">
                {patients === undefined
                  ? 'Loading patients…'
                  : patients.length === 0
                    ? 'No patients on file yet — ask your administrator to add one'
                    : 'Select a patient…'}
              </option>
              {(patients ?? []).map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </Select>
          </div>
          <Button onClick={openLog} disabled={!patientId}>
            <Plus className="h-4 w-4" />
            Log family contact
          </Button>
        </CardContent>
      </Card>

      {isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/[0.06] py-10 text-center">
          <TriangleAlert className="h-6 w-6 text-destructive" />
          <p className="text-sm text-foreground">
            Could not load the family communication log.
          </p>
          <Button variant="ghost" onClick={() => refetch()}>
            Retry
          </Button>
        </div>
      )}

      {!isError && (
        <div className="space-y-3">
          {isLoading ? (
            <Card>
              <CardContent className="p-10 text-center text-sm text-muted">
                Loading log…
              </CardContent>
            </Card>
          ) : entries.length === 0 ? (
            <Card>
              <CardContent className="p-10 text-center text-sm text-muted">
                No family conversations logged yet.
              </CardContent>
            </Card>
          ) : (
            entries.map((entry) => (
              <Card key={entry.id}>
                <CardContent className="space-y-2 px-6 py-5">
                  <header className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="text-sm font-semibold text-foreground">
                        {entry.patientName}
                      </p>
                      <p className="text-xs text-muted-soft">
                        {channel(entry.activityType, entry.activityTypeOther)}
                        {entry.author && ` · ${entry.author}`}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      {/* Stated on the row because this log is read by whoever
                          speaks to the family next, and they need to know before
                          they repeat something back. */}
                      {entry.isFamilySensitive && (
                        <span className="rounded-sm bg-warning/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-label text-warning ring-1 ring-warning/25">
                          Team only
                        </span>
                      )}
                      <span className="text-[10px] uppercase tracking-label text-muted-soft">
                        {formatDateTime(entry.createdAt)}
                      </span>
                    </div>
                  </header>
                  <p className="text-sm text-foreground">{entry.summary}</p>
                  {entry.nextStep && (
                    <p className="text-xs text-muted">
                      <span className="font-semibold text-foreground">
                        Next step:
                      </span>{' '}
                      {entry.nextStep}
                    </p>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}

      {/* The same modal the marketer logs a drop-off with, narrowed to the channels
          a family conversation actually happens on and defaulted to Phone Call —
          the guide's first example. `showFamilySensitive` surfaces the "team only"
          marker, which classifies the entry but no longer decides whether it
          appears in this log. */}
      <LogInteractionModal
        open={logOpen}
        isSaving={isSaving}
        title="Log family contact"
        target={{ prospectId: patientId }}
        showFamilySensitive
        activityTypeOptions={FAMILY_CONTACT_ACTIVITY_OPTIONS}
        defaultActivityType={ActivityType.PhoneCall}
        onClose={closeLog}
        onSubmit={submit}
      />
    </div>
  );
}
