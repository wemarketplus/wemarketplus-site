import { cn } from '@/shared/utils/cn';
import type { PasswordStrengthMeterProps } from '../types/authTypes';
import { PASSWORD_RULES, strengthOf } from '../utils/passwordStrengthUtils';
import { STRENGTH_BAR } from '../constants/authConstants';

// Mirrors wemarketplus-site/reset-password.html exactly:
//  - a 4px bar that fills 33% (weak #e05555) / 66% (mid #fbbf24) /
//    100% (strong #8cff66)
//  - a 4-item requirement list with ○ → ✓ markers, met rows in #8cff66
// Strength logic is copied verbatim from the source `checkStrength()`.

export function PasswordStrengthMeter({ value }: PasswordStrengthMeterProps) {
  const strength = strengthOf(value);
  const bar = STRENGTH_BAR[strength];

  return (
    <div>
      {/* .strength bar — 4px tall, tinted track */}
      <div className="mt-1.5 h-1 overflow-hidden rounded-[2px] bg-primary/[0.08]">
        <div className={cn('h-full rounded-[2px] transition-all duration-200', bar.width, bar.color)} />
      </div>
      <div className="mt-1 text-[11px] text-muted">{bar.label}</div>

      {/* .req-list — ○/✓ markers, met rows in the success accent */}
      <ul className="mt-1.5 list-none text-[11px] text-muted">
        {PASSWORD_RULES.map((r) => {
          const met = r.test(value);
          return (
            <li
              key={r.key}
              className={cn('py-0.5 transition-colors', met && 'text-success')}
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
