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

// Standard trailing edit/delete controls for a DataTable row. Drop this into an
// `actions` column's `cell` and gate the handlers with role checks upstream.
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
        >
          <Pencil className="h-4 w-4 text-muted" />
        </Button>
      )}
      {onDelete && (
        <Button
          variant="ghost"
          size="square"
          onClick={onDelete}
          disabled={disabled}
          aria-label={deleteLabel}
        >
          <Trash2 className="h-4 w-4 text-destructive" />
        </Button>
      )}
    </div>
  );
}
