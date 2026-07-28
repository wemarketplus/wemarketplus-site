import { useMemo, useState } from 'react';
import { Gift } from 'lucide-react';
import { Button, Card, CardContent, Input } from '@/shared/ui/core';
import { EmptyState } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
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

  const canSave = Boolean(recipientName.trim() && visitDate && giftType.trim() && giftValue) && !isSaving;

  const save = async () => {
    if (!canSave) return;
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
    setGiftType('');
    setGiftValue('');
    setVisitPurpose('');
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Gift & gratuity</h1>
        <p className="text-sm text-muted">Anti-kickback compliance log for referral-source gifts.</p>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card>
          <CardContent className="space-y-1 px-6 py-5">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">Total logged</p>
            <p className="font-display text-3xl leading-none text-foreground">{logs.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="space-y-1 px-6 py-5">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">Total value</p>
            <p className="font-display text-3xl leading-none text-foreground">${totalValue.toFixed(2)}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="space-y-1 px-6 py-5">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">Compliance violations</p>
            <p className={`font-display text-3xl leading-none ${violations > 0 ? 'text-destructive' : 'text-foreground'}`}>
              {violations}
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="space-y-3 pt-6">
          <h2 className="text-sm font-bold text-foreground">Log gift / gratuity</h2>
          {saveError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(saveError, 'Failed to save log')}
            </p>
          )}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Input placeholder="Recipient name *" value={recipientName} onChange={(e) => setRecipientName(e.target.value)} />
            <Input placeholder="Facility" value={facilityName} onChange={(e) => setFacilityName(e.target.value)} />
            <Input type="date" aria-label="Visit date" value={visitDate} onChange={(e) => setVisitDate(e.target.value)} />
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
            <div className="rounded-[14px] border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : logs.length === 0 ? (
            <EmptyState icon={Gift} title="No gift logs yet" description="Log a gift or gratuity to keep the compliance trail current." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-[0.08em] text-muted-soft">
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
                      <td className="py-2 pr-3">
                        <p className="font-semibold text-foreground">{l.recipientName}</p>
                        {l.facilityName && <p className="text-[11px] text-muted-soft">{l.facilityName}</p>}
                      </td>
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
