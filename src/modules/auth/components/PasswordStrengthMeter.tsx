import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site/reset-password.html exactly:
//  - a 4px bar that fills 33% (weak #e05555) / 66% (mid #fbbf24) /
//    100% (strong #8cff66)
//  - a 4-item requirement list with ○ → ✓ markers, met rows in #8cff66
// Strength logic is copied verbatim from the source `checkStrength()`.

interface Rule {
  key: string;
  label: string;
  test: (v: string) => boolean;
}

const RULES: readonly Rule[] = [
  { key: 'r1', label: 'At least 8 characters', test: (v) => v.length >= 8 },
  { key: 'r2', label: 'At least one uppercase letter', test: (v) => /[A-Z]/.test(v) },
  { key: 'r3', label: 'At least one number', test: (v) => /[0-9]/.test(v) },
  { key: 'r4', label: 'At least one special character', test: (v) => /[^a-zA-Z0-9]/.test(v) },
];

type Strength = 'none' | 'weak' | 'mid' | 'strong';

function strengthOf(v: string): Strength {
  if (!v) return 'none';
  const strong =
    v.length >= 10 && /[A-Z]/.test(v) && /[0-9]/.test(v) && /[^a-zA-Z0-9]/.test(v);
  const mid = v.length >= 8 && (/[A-Z]/.test(v) || /[0-9]/.test(v));
  if (strong) return 'strong';
  if (mid) return 'mid';
  return 'weak';
}

const BAR: Record<Strength, { width: string; color: string; label: string }> = {
  none: { width: 'w-0', color: '', label: '' },
  weak: { width: 'w-1/3', color: 'bg-[#e05555]', label: 'Weak' },
  mid: { width: 'w-2/3', color: 'bg-[#fbbf24]', label: 'Medium' },
  strong: { width: 'w-full', color: 'bg-[#8cff66]', label: 'Strong ✓' },
};

export function PasswordStrengthMeter({ value }: { value: string }) {
  const strength = strengthOf(value);
  const bar = BAR[strength];

  return (
    <div>
      {/* .strength bar — 4px tall, #12253d track */}
      <div className="mt-1.5 h-1 overflow-hidden rounded-[2px] bg-[#12253d]">
        <div className={cn('h-full rounded-[2px] transition-all duration-200', bar.width, bar.color)} />
      </div>
      <div className="mt-1 text-[11px] text-muted">{bar.label}</div>

      {/* .req-list — ○/✓ markers, met rows in #8cff66 */}
      <ul className="mt-1.5 list-none text-[11px] text-muted">
        {RULES.map((r) => {
          const met = r.test(value);
          return (
            <li
              key={r.key}
              className={cn('py-0.5 transition-colors', met && 'text-[#8cff66]')}
            >
              <span className="text-[10px]">{met ? '✓ ' : '○ '}</span>
              {r.label}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
