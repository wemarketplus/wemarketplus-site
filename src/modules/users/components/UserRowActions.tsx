import { KeyRound, MailPlus, MoreVertical, Pencil, Power, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { cn } from '@/shared/utils/cn';
import type { UserRecord } from '../types/usersTypes';
import { fullName } from '../utils/userDisplay';

interface UserRowActionsProps {
  user: UserRecord;
  disabled: boolean;
  onEdit: (user: UserRecord) => void;
  onResetPassword: (user: UserRecord) => void;
  onResendInvite: (user: UserRecord) => void;
  onToggleActive: (user: UserRecord, next: boolean) => void;
  onDelete: (user: UserRecord) => void;
  // Whether the current viewer may hard-delete (super admin). Delete is hidden
  // otherwise, matching the backend's SuperAdmin-only DELETE /users/:id.
  canDelete: boolean;
}

// Per-row actions menu for the users table. A single trigger opens a small
// popover of the mutations the backend supports (edit, reset password, resend
// invite, deactivate/reactivate, delete). Closes on outside click / Escape.
export function UserRowActions({
  user,
  disabled,
  onEdit,
  onResetPassword,
  onResendInvite,
  onToggleActive,
  onDelete,
  canDelete,
}: UserRowActionsProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const run = (fn: () => void) => () => {
    setOpen(false);
    fn();
  };

  const itemClass =
    'flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-[13px] text-foreground transition-colors hover:bg-foreground/[0.06] disabled:opacity-40';

  return (
    <div ref={ref} className="relative inline-block text-left">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Actions for ${fullName(user)}`}
        className="flex h-9 w-9 items-center justify-center rounded-md text-muted transition-colors hover:bg-foreground/[0.06] hover:text-foreground disabled:opacity-40"
      >
        <MoreVertical className="h-4 w-4" />
      </button>

      {open && (
        <div
          role="menu"
          className={cn(
            'absolute right-0 z-20 mt-1 w-52 overflow-hidden rounded-lg border border-border/[0.1] bg-surface py-1 shadow-2xl',
          )}
        >
          <button type="button" role="menuitem" className={itemClass} onClick={run(() => onEdit(user))}>
            <Pencil className="h-4 w-4 text-muted" /> Edit user
          </button>
          <button
            type="button"
            role="menuitem"
            className={itemClass}
            onClick={run(() => onResetPassword(user))}
          >
            <KeyRound className="h-4 w-4 text-muted" /> Reset password
          </button>
          <button
            type="button"
            role="menuitem"
            className={itemClass}
            onClick={run(() => onResendInvite(user))}
          >
            <MailPlus className="h-4 w-4 text-muted" /> Resend invite
          </button>
          <button
            type="button"
            role="menuitem"
            className={itemClass}
            onClick={run(() => onToggleActive(user, !user.isActive))}
          >
            <Power className="h-4 w-4 text-muted" />
            {user.isActive ? 'Deactivate' : 'Reactivate'}
          </button>
          {canDelete && (
            <>
              <div className="my-1 border-t border-border/[0.07]" />
              <button
                type="button"
                role="menuitem"
                className={cn(itemClass, 'text-destructive hover:bg-destructive/10')}
                onClick={run(() => onDelete(user))}
              >
                <Trash2 className="h-4 w-4" /> Delete user
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
