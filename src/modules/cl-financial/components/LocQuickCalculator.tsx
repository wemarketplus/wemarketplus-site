import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { Card, CardContent, Checkbox, Input, Select } from '@/shared/ui/core';
import { formatUsd } from '../utils/financialFormat';
import { num } from '../utils/clFinancialMappers';
import type { ClLocPricingRecord } from '../types/clFinancialApiTypes';

const SECOND_PERSON_FEE = 600;

interface LocQuickCalculatorProps {
  levels: readonly ClLocPricingRecord[];
}

// Quick Rate Calculator (Max tier): pick a level-of-care tier, optionally add
// a second-person fee and parking, and see the computed monthly total —
// matches the demo's "Quick Rate Calculator" widget, adapted to the real
// cl/loc-pricing data model (per-level add-on rate, not a separate base-rate
// table).
export function LocQuickCalculator({ levels }: LocQuickCalculatorProps) {
  const [levelId, setLevelId] = useState('');
  const [secondPerson, setSecondPerson] = useState(false);
  const [parking, setParking] = useState('');

  const level = useMemo(() => levels.find((l) => l.id === levelId), [levels, levelId]);

  const total = useMemo(() => {
    if (!level) return null;
    const parkingFee = Number(parking) || 0;
    return num(level.addOnRate) + (secondPerson ? SECOND_PERSON_FEE : 0) + parkingFee;
  }, [level, secondPerson, parking]);

  return (
    <Card>
      <CardContent className="space-y-3 pt-6">
        <h2 className={SECTION_TITLE}>Quick rate calculator</h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Select value={levelId} onChange={(e) => setLevelId(e.target.value)} aria-label="Level of care">
            <option value="">Select a level…</option>
            {levels.map((l) => (
              <option key={l.id} value={l.id}>
                Level {l.level} — {l.label}
              </option>
            ))}
          </Select>
          <label className="flex items-center gap-2 text-sm text-muted">
            <Checkbox
              checked={secondPerson}
              onChange={(e) => setSecondPerson(e.target.checked)}
            />
            Second person (+{formatUsd(SECOND_PERSON_FEE)})
          </label>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted">Parking $</span>
            {/*
              <Input>, not a hand-rolled <input>. This restated CONTROL_BASE by
              hand and got three things wrong at once: `py-2` with no height
              (34px against the <Select>'s 44px, and the two share this grid
              row), `border-border/10` against the shared `/[0.12]`, and
              `bg-surface` against `bg-surface-raised` — so it read as a
              lighter, shorter, differently-outlined control beside its own
              dropdown. See controlStyles.ts.
            */}
            <Input
              type="number"
              step="0.01"
              value={parking}
              onChange={(e) => setParking(e.target.value)}
              aria-label="Parking fee"
            />
          </div>
        </div>
        {total != null && (
          <div className="rounded-md border border-primary/30 bg-primary/10 px-4 py-3">
            <p className="text-[10px] uppercase tracking-label text-muted-soft">Estimated monthly total</p>
            <p className="font-display text-2xl text-foreground">{formatUsd(total)}/mo</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
