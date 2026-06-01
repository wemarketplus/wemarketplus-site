import { Check } from 'lucide-react';
import { STEP_LABELS, STEP_ORDER } from '../constants/onboardingConstants';
import { cn } from '@/shared/utils/cn';
import type { OnboardingStep } from '../types/onboardingTypes';

interface WizardProgressProps {
  current: OnboardingStep;
}

export function WizardProgress({ current }: WizardProgressProps) {
  const currentIndex = STEP_ORDER.indexOf(current);
  const progress = ((currentIndex + 1) / STEP_ORDER.length) * 100;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
          Step {currentIndex + 1} of {STEP_ORDER.length}
        </p>
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">
          {Math.round(progress)}% complete
        </p>
      </div>
      <div className="h-1 w-full overflow-hidden rounded-pill bg-white/[0.06]">
        <div
          className="h-full rounded-pill bg-gradient-to-r from-primary to-azure transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>
      <ol className="grid grid-cols-4 gap-2">
        {STEP_ORDER.map((step, i) => {
          const done = i < currentIndex;
          const active = i === currentIndex;
          return (
            <li
              key={step}
              className={cn(
                'flex flex-col items-center gap-1.5 text-center transition-colors',
                active && 'text-foreground',
                !active && !done && 'text-muted-soft',
                done && 'text-primary',
              )}
            >
              <span
                className={cn(
                  'flex h-7 w-7 items-center justify-center rounded-full border text-[11px] font-semibold transition-colors',
                  active && 'border-primary bg-primary/15 text-primary',
                  done && 'border-primary bg-primary text-primary-foreground',
                  !active && !done && 'border-white/[0.08] bg-white/[0.02]',
                )}
              >
                {done ? <Check className="h-3.5 w-3.5" /> : i + 1}
              </span>
              <span className="text-[10px] uppercase tracking-[0.1em]">
                {STEP_LABELS[step]}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
