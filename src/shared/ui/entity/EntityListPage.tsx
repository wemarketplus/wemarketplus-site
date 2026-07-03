import type { ReactNode } from 'react';
import { Plus } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';

interface EntityListPageProps {
  // Page heading + subheading.
  title: string;
  subtitle?: ReactNode;
  // Add-button label. Omit `onAdd` to hide the button (e.g. read-only role).
  addLabel?: string;
  onAdd?: () => void;
  // Extra actions rendered next to the Add button (e.g. a Dedup button).
  actions?: ReactNode;
  // Filter controls rendered above the table.
  filters?: ReactNode;
  // The table (usually an EntityTable).
  children: ReactNode;
  // Query state. `error` is the raw RTK Query error; it's flattened here.
  isLoading?: boolean;
  error?: unknown;
  errorFallback?: string;
  // Pagination footer (usually <EntityPagination/>). Omit for unpaginated lists.
  pagination?: ReactNode;
}

// Scaffold shared by every entity CRUD page: header (title + subtitle + Add +
// extra actions), a card wrapping the filters slot, an inline error banner, the
// table (passed as children), and an optional pagination footer. A new module
// supplies its own filters/table/pagination and wires the query state — see
// `modules/contacts/pages/ContactsPage.tsx` for the reference usage.
export function EntityListPage({
  title,
  subtitle,
  addLabel,
  onAdd,
  actions,
  filters,
  children,
  isLoading,
  error,
  errorFallback = 'Failed to load records',
  pagination,
}: EntityListPageProps) {
  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex flex-col gap-1">
          <h1 className="font-display text-3xl text-foreground">{title}</h1>
          {subtitle && <p className="text-sm text-muted">{subtitle}</p>}
        </div>
        {(onAdd || actions) && (
          <div className="flex items-center gap-2">
            {actions}
            {onAdd && (
              <Button onClick={onAdd}>
                <Plus className="h-4 w-4" /> {addLabel ?? 'Add'}
              </Button>
            )}
          </div>
        )}
      </header>

      <Card>
        <CardContent className="space-y-5 pt-6">
          {filters}

          {error ? (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(error, errorFallback)}
            </p>
          ) : null}

          {isLoading ? (
            <div className="rounded-[12px] border border-white/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : (
            children
          )}

          {pagination}
        </CardContent>
      </Card>
    </div>
  );
}
