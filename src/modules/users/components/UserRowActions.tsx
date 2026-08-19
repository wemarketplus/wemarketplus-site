import { KeyRound, MailPlus, MoreVertical, Pencil, Power, Trash2 } from 'lucide-react';
import { DropdownMenu } from '@/shared/ui/feedback';
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
// invite, deactivate/reactivate, delete).
//
// The menu itself is the shared DropdownMenu, which portals to document.body:
// this used to be an `absolute` div inside the row, which DataTable's
// `overflow-hidden` corner-clipping wrapper silently cut off on the lower rows —
// the menu opened, but into invisible space. See DropdownMenu for the details.
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
  const itemClass =
    'flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-[13px] text-foreground transition-colors hover:bg-foreground/[0.06] disabled:opacity-40';

  return (
    <DropdownMenu
      trigger={(props) => (
        <button
          {...props}
          type="button"
          disabled={disabled}
          aria-label={`Actions for ${fullName(user)}`}
          className="flex h-9 w-9 items-center justify-center rounded-md text-muted transition-colors hover:bg-foreground/[0.06] hover:text-foreground disabled:opacity-40"
        >
          <MoreVertical className="h-4 w-4" />
        </button>
      )}
    >
      {(close) => {
        const run = (fn: () => void) => () => {
          close();
          fn();
        };
        return (
          <>
            <button
              type="button"
              role="menuitem"
              className={itemClass}
              onClick={run(() => onEdit(user))}
            >
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
          </>
        );
      }}
    </DropdownMenu>
  );
}
