import { Link } from 'react-router-dom';
import { ArrowRight, Check, PartyPopper, X } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { useOnboardingChecklist } from '../hooks/useOnboardingChecklist';

// Dismissible getting-started card for new tenants. Renders on the dashboard
// only while there is at least one open step and it has not been dismissed
// (see useOnboardingChecklist.isVisible). Each step deep-links to the page that
// completes it and auto-checks from real tenant data.
export function OnboardingChecklistCard() {
  const { steps, completed, total, progress, isVisible, justCompleted, dismiss } =
    useOnboardingChecklist();

  if (!isVisible) return null;

  if (justCompleted) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-3 py-8 text-center">
          <span className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 text-primary">
            <PartyPopper className="h-6 w-6" />
          </span>
          <div className="space-y-1">
            <h2 className="font-display text-xl text-foreground">
              You are all set up
            </h2>
            <p className="mx-auto max-w-sm text-[13px] text-muted">
              Every getting-started step is done. Your workspace is ready to run.
            </p>
          </div>
          <Button size="sm" variant="secondary" onClick={dismiss} className="mt-1">
            Dismiss
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="space-y-5 pt-6">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="font-display text-xl text-foreground">
              Get set up in a few steps
            </h2>
            <p className="mt-0.5 text-[13px] text-muted">
              Finish these to get real value out of your workspace.
            </p>
          </div>
          <button
            type="button"
            onClick={dismiss}
            aria-label="Dismiss getting started checklist"
            className="rounded-md p-1.5 text-muted transition-colors hover:bg-foreground/[0.06] hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-[12px] text-muted">
            <span>
              {completed} of {total} complete
            </span>
            <span>{progress}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-pill bg-foreground/[0.08]">
            <div
              className="h-full rounded-pill bg-primary transition-[width] duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        <ul className="space-y-2">
          {steps.map((step) => {
            const Icon = step.icon;
            return (
              <li key={step.id}>
                <Link
                  to={step.to}
                  className={cn(
                    'group flex items-center gap-3 rounded-[14px] border border-border/[0.08] bg-surface px-3.5 py-3 transition-colors',
                    step.done
                      ? 'opacity-70'
                      : 'hover:border-primary/40 hover:bg-foreground/[0.03]',
                  )}
                >
                  <span
                    className={cn(
                      'flex h-8 w-8 shrink-0 items-center justify-center rounded-full',
                      step.done
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-primary/10 text-primary',
                    )}
                  >
                    {step.done ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Icon className="h-4 w-4" />
                    )}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p
                      className={cn(
                        'text-[14px] font-bold text-foreground',
                        step.done && 'line-through',
                      )}
                    >
                      {step.title}
                    </p>
                    <p className="truncate text-[12px] text-muted">
                      {step.description}
                    </p>
                  </div>
                  {!step.done && (
                    <span className="flex items-center gap-1 text-[12px] font-bold text-primary opacity-0 transition-opacity group-hover:opacity-100">
                      {step.ctaLabel}
                      <ArrowRight className="h-3.5 w-3.5" />
                    </span>
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}
