import { PAGE_TITLE, SECTION_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { Gift } from 'lucide-react';
import { Button, Card, CardContent, DatePicker, Input } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import { useCreateGiftGratuityLogMutation, useListGiftGratuityLogsQuery } from '../api/giftGratuityApi';

const PAGE_SIZE = 50;

// Gift & Gratuity (Max tier): an append-only anti-kickback compliance log —
// entries are never edited or deleted. The backend computes complianceOk /
// limitAtTime against the tenant's gift_gratuity_limit financial setting.
export function GiftGratuityPage() {
  const { data, isLoading, error } = useListGiftGratuityLogsQuery({ page: 1, limit: PAGE_SIZE });
  const logs = useMemo(() => data?.data ?? [], [data]);
  const totalValue = useMemo(() => logs.reduce((s, l) => s + Number(l.giftValue), 0), [logs]);
  const violations = useMemo(() => logs.filter((l) => !l.complianceOk).length, [logs]);

  const [createLog, { isLoading: isSaving, error: saveError }] = useCreateGiftGratuityLogMutation();
  const [recipientName, setRecipientName] = useState('');
  const [facilityName, setFacilityName] = useState('');
  const [visitDate, setVisitDate] = useState('');
  const [giftType, setGiftType] = useState('');
  const [giftValue, setGiftValue] = useState('');
  const [visitPurpose, setVisitPurpose] = useState('');
  // Client-side validation message for the visit date. This page is plain
  // useState rather than react-hook-form, so there is no formState to hang a
  // field error on — one piece of state, cleared as soon as the date changes.
  const [dateError, setDateError] = useState('');

  const canSave = Boolean(recipientName.trim() && visitDate && giftType.trim() && giftValue) && !isSaving;

  const save = async () => {
    if (!canSave) return;
    /**
     * A gift cannot be logged against a day that has already passed.
     *
     * There was no check anywhere: a past date saved silently and then sat in the
     * Date column of the log, which is the reported behaviour ("the date section
     * shows a past date while the record is successfully saved"). On an
     * anti-kickback register the visit date is the one field where a back-date is
     * not a clerical convenience — the log is meant to be the contemporaneous
     * record of what was given and when.
     *
     * The middle of the same three layers the other date fields use: `min` on the
     * picker below greys out past days, and @IsNotPastDate on
     * CreateGiftGratuityLogDto is what actually holds the rule — so the same
     * value cannot be slipped in by posting straight to the API either. This
     * layer only exists so a TYPED past date reads as a sentence next to the
     * field instead of a 400 from the server.
     *
     * This log is append-only (no edit path exists), so unlike the task and
     * ledger dates there is no "only when the date changed" case to carve out.
     */
    if (visitDate < todayLocalDate()) {
      setDateError('Visit date cannot be in the past.');
      return;
    }
    setDateError('');
    await createLog({
      recipientName: recipientName.trim(),
      facilityName: facilityName.trim() || undefined,
      visitDate,
      giftType: giftType.trim(),
      giftValue: Number(giftValue),
      visitPurpose: visitPurpose.trim() || undefined,
    }).unwrap();
    setRecipientName('');
    setFacilityName('');
    setVisitDate('');
    setDateError('');
    setGiftType('');
    setGiftValue('');
    setVisitPurpose('');
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Gift & gratuity</h1>
        <p className="text-sm text-muted">Anti-kickback compliance log for referral-source gifts.</p>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card>
          <CardContent className="space-y-1 px-6 py-5">
            <p className="text-[10px] uppercase tracking-label text-muted-soft">Total logged</p>
            <p className="font-display text-3xl leading-none text-foreground">{logs.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="space-y-1 px-6 py-5">
            <p className="text-[10px] uppercase tracking-label text-muted-soft">Total value</p>
            <p className="font-display text-3xl leading-none text-foreground">${totalValue.toFixed(2)}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="space-y-1 px-6 py-5">
            <p className="text-[10px] uppercase tracking-label text-muted-soft">Compliance violations</p>
            <p className={`font-display text-3xl leading-none ${violations > 0 ? 'text-destructive' : 'text-foreground'}`}>
              {violations}
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="space-y-3 pt-6">
          <h2 className={SECTION_TITLE}>Log gift / gratuity</h2>
          {saveError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(saveError, 'Failed to save log')}
            </p>
          )}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input placeholder="Recipient name *" value={recipientName} onChange={(e) => setRecipientName(e.target.value)} />
            <Input placeholder="Facility" value={facilityName} onChange={(e) => setFacilityName(e.target.value)} />
            <div>
              {/* `min` greys out past days in the calendar itself — the same
                  floor the task, lead and housekeeping dates use. Read fresh on
                  each render, so a page left open across midnight does not still
                  offer yesterday. */}
              <DatePicker
                aria-label="Visit date"
                min={todayLocalDate()}
                value={visitDate}
                onChange={(e) => {
                  setVisitDate(e.target.value);
                  setDateError('');
                }}
              />
              {dateError && <p className="mt-1 text-[12px] text-destructive">{dateError}</p>}
            </div>
            <Input placeholder="Gift type *" value={giftType} onChange={(e) => setGiftType(e.target.value)} />
            <Input type="number" step="0.01" placeholder="Gift value ($) *" value={giftValue} onChange={(e) => setGiftValue(e.target.value)} />
            <Input placeholder="Visit purpose" value={visitPurpose} onChange={(e) => setVisitPurpose(e.target.value)} />
          </div>
          <Button onClick={save} disabled={!canSave}>
            Save gift log
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 pt-6">
          {error ? (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              Failed to load gift/gratuity logs.
            </p>
          ) : isLoading ? (
            <div className="rounded-card border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : logs.length === 0 ? (
            <EmptyState icon={Gift} title="No gift logs yet" description="Log a gift or gratuity to keep the compliance trail current." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-label text-muted-soft">
                    <th className="pb-2 pr-3">Date</th>
                    <th className="pb-2 pr-3">Recipient</th>
                    <th className="pb-2 pr-3">Type</th>
                    <th className="pb-2 pr-3">Value</th>
                    <th className="pb-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.id} className="border-t border-border/[0.06]">
                      <td className="py-2 pr-3 text-[12px] text-muted">{l.visitDate}</td>
                      {/* The Recipient cell says WHO received the gift. The
                          facility was stacked under the name, which is the
                          "facility details incorrectly displayed in the receipt"
                          report — on an anti-kickback log a facility printed
                          under a person's name reads as part of that person's
                          identity, and this log's job is to be unambiguous about
                          who was given what. Facility is still collected on the
                          entry (the Facility input above) and stored on the
                          record; it is simply not part of the recipient. */}
                      <td className="py-2 pr-3 font-semibold text-foreground">{l.recipientName}</td>
                      <td className="py-2 pr-3 text-[12px] text-muted">{l.giftType}</td>
                      <td className={`py-2 pr-3 font-bold ${l.complianceOk ? 'text-foreground' : 'text-destructive'}`}>
                        ${Number(l.giftValue).toFixed(2)}
                      </td>
                      <td className="py-2">
                        <span
                          className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-bold ${
                            l.complianceOk ? 'bg-success/10 text-success' : 'bg-destructive/10 text-destructive'
                          }`}
                        >
                          {l.complianceOk ? 'OK' : 'Over limit'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
