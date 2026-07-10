import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';

interface EmptyStateProps {
  // Optional glyph rendered in a soft accent halo above the title.
  icon?: LucideIcon;
  title: string;
  // One-line suggestion of what to do next — the "why this is empty + fix".
  description?: ReactNode;
  // Single primary CTA. Omit both to render a purely informational empty state.
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

// Intentional empty state: context (icon + title) + a suggestion (description) +
// a single call to action. Used inside DataTable's `empty` slot and on the
// dashboard so a zero-data tenant always sees a next step rather than a void.
export function EmptyState({
  icon: Icon,
  title,
  description,
  actionLabel,
  onAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center gap-3 px-6 py-10 text-center',
        className,
      )}
    >
      {Icon && (
        <span className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 text-primary">
          <Icon className="h-6 w-6" />
        </span>
      )}
      <div className="space-y-1">
        <p className="text-[15px] font-bold text-foreground">{title}</p>
        {description && (
          <p className="mx-auto max-w-sm text-[13px] text-muted">{description}</p>
        )}
      </div>
      {actionLabel && onAction && (
        <Button size="sm" onClick={onAction} className="mt-1">
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
