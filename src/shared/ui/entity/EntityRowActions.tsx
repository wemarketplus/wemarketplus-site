import { Pencil, Trash2 } from 'lucide-react';
import { Button } from '@/shared/ui/core';

interface EntityRowActionsProps {
  // Omit a handler to hide that action (e.g. delete gated to admins).
  onEdit?: () => void;
  onDelete?: () => void;
  disabled?: boolean;
  editLabel?: string;
  deleteLabel?: string;
}

/**
 * Standard trailing edit/delete controls for a DataTable row. Drop this into an
 * `actions` column's `cell` and gate the handlers with role checks upstream.
 *
 * The icons were 16px glyphs in `text-muted`, which put the two things a user
 * most often wants to DO with a row at a lower visual weight than the row's own
 * body text — they read as decoration rather than controls, and on a dense table
 * they were genuinely hard to aim at.
 *
 * What changed, and what deliberately did not:
 *   - 18px glyphs in a 36px hit area. The button was already 36px (`square`), so
 *     the CLICK target is unchanged and still comfortably above the 24px minimum
 *     — this buys legibility, not size.
 *   - A visible hover/focus surface, so the control announces itself as a
 *     control before it is clicked.
 *   - Delete keeps `text-destructive` at rest and deepens on hover. It is NOT
 *     given a permanent red fill: a red block on every row makes deletion look
 *     like the primary action of the table, and the confirm dialog is the real
 *     safeguard.
 */
export function EntityRowActions({
  onEdit,
  onDelete,
  disabled,
  editLabel = 'Edit',
  deleteLabel = 'Delete',
}: EntityRowActionsProps) {
  return (
    <div className="flex items-center justify-end gap-1">
      {onEdit && (
        <Button
          variant="ghost"
          size="square"
          onClick={onEdit}
          disabled={disabled}
          aria-label={editLabel}
          title={editLabel}
          className="text-muted hover:bg-primary/[0.08] hover:text-primary"
        >
          <Pencil className="h-[18px] w-[18px]" />
        </Button>
      )}
      {onDelete && (
        <Button
          variant="ghost"
          size="square"
          onClick={onDelete}
          disabled={disabled}
          aria-label={deleteLabel}
          title={deleteLabel}
          className="text-destructive/80 hover:bg-destructive/[0.1] hover:text-destructive"
        >
          <Trash2 className="h-[18px] w-[18px]" />
        </Button>
      )}
    </div>
  );
}
