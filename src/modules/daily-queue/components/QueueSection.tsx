import type { ComponentType, ReactNode } from 'react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';

interface QueueSectionProps {
  title: string;
  /** Why this section exists, in the user's terms — not a restatement of the title. */
  subtitle: string;
  icon: ComponentType<{ className?: string }>;
  count: number;
  /** Shown instead of the list when the section is empty. */
  emptyLabel: string;
  /** Draws attention when the section represents neglected work. */
  urgent?: boolean;
  children: ReactNode;
}

/**
 * One block of the daily queue.
 *
 * Every section renders even when empty, and says so. A queue that hides its
 * empty sections looks identical whether the marketer has cleared their cold
 * accounts or the feature has quietly broken — and "nothing to do" is a real,
 * useful answer that the user should be able to trust.
 */
export function QueueSection({
  title,
  subtitle,
  icon: Icon,
  count,
  emptyLabel,
  urgent = false,
  children,
}: QueueSectionProps) {
  return (
    <Card>
      <CardContent className="px-0 pb-0 pt-0">
        <header className="flex flex-wrap items-center gap-3 px-6 py-4">
          <span
            className={
              urgent && count > 0
                ? 'rounded-[10px] bg-destructive/[0.10] p-2 text-destructive'
                : 'rounded-[10px] bg-primary/[0.08] p-2 text-primary'
            }
          >
            <Icon className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-foreground">{title}</h2>
            <p className="text-[11px] text-muted-soft">{subtitle}</p>
          </div>
          {count > 0 && (
            <Pill tone={urgent ? 'r' : 'b'}>{count}</Pill>
          )}
        </header>

        {count === 0 ? (
          <p className="px-6 pb-5 text-xs text-muted-soft">{emptyLabel}</p>
        ) : (
          <div className="border-t border-border">{children}</div>
        )}
      </CardContent>
    </Card>
  );
}
