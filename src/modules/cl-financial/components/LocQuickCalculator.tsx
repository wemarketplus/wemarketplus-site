import { useMemo, useState } from 'react';
import { Card, CardContent, Checkbox, Select } from '@/shared/ui/core';
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
        <h2 className="text-sm font-bold text-foreground">Quick rate calculator</h2>
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
            <input
              type="number"
              step="0.01"
              value={parking}
              onChange={(e) => setParking(e.target.value)}
              className="w-full rounded-md border border-border/10 bg-surface px-3 py-2 text-sm text-foreground outline-none focus:border-primary/50"
              aria-label="Parking fee"
            />
          </div>
        </div>
        {total != null && (
          <div className="rounded-md border border-primary/30 bg-primary/10 px-4 py-3">
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">Estimated monthly total</p>
            <p className="font-display text-2xl text-foreground">{formatUsd(total)}/mo</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
