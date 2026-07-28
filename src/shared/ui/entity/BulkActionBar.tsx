import { Trash2, X } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import type { BulkDeleteProgress } from './useBulkDelete';

interface BulkActionBarProps {
  count: number;
  noun: string;
  // Plural form when it is not simply `${noun}s` (e.g. "companies").
  nounPlural?: string;
  // Omit to hide the bulk-delete button (e.g. role-gated).
  onDelete?: () => void;
  onClear: () => void;
  isDeleting?: boolean;
  progress?: BulkDeleteProgress | null;
}

// Selection toolbar shown above a list table when one or more rows are
// selected. Renders the count, a Bulk delete action, and a clear-selection
// control. Additive to the entity kit — a page renders it only when a selection
// exists, so lists that don't opt into selection never see it.
export function BulkActionBar({
  count,
  noun,
  nounPlural,
  onDelete,
  onClear,
  isDeleting,
  progress,
}: BulkActionBarProps) {
  if (count === 0) return null;

  const label = count === 1 ? noun : (nounPlural ?? `${noun}s`);

  return (
    <div className="flex items-center justify-between gap-3 rounded-[14px] border border-primary/25 bg-primary/[0.08] px-4 py-2.5">
      <div className="flex items-center gap-2 text-[13px] text-foreground">
        <button
          type="button"
          onClick={onClear}
          aria-label="Clear selection"
          className="flex h-6 w-6 items-center justify-center rounded-full text-muted hover:bg-foreground/[0.06] hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
        <span className="font-semibold">
          {count} {label} selected
        </span>
        {isDeleting && progress && (
          <span className="text-[12px] text-muted">
            Deleting {progress.done}/{progress.total}…
          </span>
        )}
      </div>

      {onDelete && (
        <Button
          variant="destructive"
          size="sm"
          onClick={onDelete}
          disabled={isDeleting}
        >
          <Trash2 className="h-4 w-4" />
          {isDeleting ? 'Deleting…' : 'Delete selected'}
        </Button>
      )}
    </div>
  );
}
