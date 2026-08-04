import { Check, Lock, X } from 'lucide-react';
import { ALL_ROLES, Role, ROLE_LABELS } from '@/shared/rbac';
import { cn } from '@/shared/utils/cn';
import {
  PERMISSION_KEYS,
  PERMISSION_LABELS,
  type PermissionKey,
} from '../constants/permissionMatrixKeys';
import type { PermissionMatrix } from '../types/permissionsApiTypes';

interface PermissionMatrixGridProps {
  permissions: PermissionMatrix;
  locked: PermissionMatrix;
  /** Cells THIS actor may not change, though a super admin could. */
  restricted: PermissionMatrix;
  canEdit: boolean;
  pendingCell: string | null;
  onToggle: (permission: PermissionKey, role: Role, value: boolean) => void;
}

// Why a cell isn't editable — drives the tooltip, so "nobody can change this" and
// "you can't change this" stop looking like the same thing.
type LockReason = 'read-only' | 'locked' | 'restricted' | null;

// Both matrices mark a cell by PRESENCE, not by value: a cell is closed when the
// key exists at all, matching how the backend reads LOCKED_PERMISSIONS. `locked`
// and `restricted` both come from the server, so the grid no longer guesses which
// cells the API would reject — it is told.
function lockReasonFor(
  locked: PermissionMatrix,
  restricted: PermissionMatrix,
  permission: PermissionKey,
  role: Role,
  canEdit: boolean,
): LockReason {
  if (!canEdit) return 'read-only';
  if (locked[permission]?.[role] !== undefined) return 'locked';
  if (restricted[permission]?.[role] !== undefined) return 'restricted';
  return null;
}

const LOCK_TITLES: Record<Exclude<LockReason, null>, string> = {
  'read-only': 'You do not have permission to edit this matrix',
  locked: 'Locked — cannot be changed by anyone',
  restricted: 'Only a super admin can change this',
};

// Presentational RBAC matrix: rows = permission keys, columns = roles, cells =
// effective allow/deny. Editable cells are checkboxes; locked cells render a
// static allow/deny badge with a lock affordance and tooltip.
export function PermissionMatrixGrid({
  permissions,
  locked,
  restricted,
  canEdit,
  pendingCell,
  onToggle,
}: PermissionMatrixGridProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border/[0.08]">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-border/[0.08] bg-foreground/[0.02]">
            <th className="sticky left-0 z-10 bg-surface px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.08em] text-muted">
              Permission
            </th>
            {ALL_ROLES.map((role) => (
              <th
                key={role}
                className="px-3 py-3 text-center text-xs font-semibold text-foreground"
              >
                {ROLE_LABELS[role]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PERMISSION_KEYS.map((permission) => (
            <tr
              key={permission}
              className="border-b border-border/[0.05] last:border-b-0 hover:bg-foreground/[0.02]"
            >
              <th
                scope="row"
                className="sticky left-0 z-10 bg-surface px-4 py-3 text-left text-[13px] font-medium text-foreground"
              >
                {PERMISSION_LABELS[permission]}
              </th>
              {ALL_ROLES.map((role) => {
                const allowed = permissions[permission]?.[role] === true;
                const lockReason = lockReasonFor(
                  locked,
                  restricted,
                  permission,
                  role,
                  canEdit,
                );
                const cellId = `${permission}:${role}`;
                const isPending = pendingCell === cellId;

                return (
                  <td key={role} className="px-3 py-3 text-center">
                    <PermissionCell
                      allowed={allowed}
                      lockReason={lockReason}
                      pending={isPending}
                      label={`${PERMISSION_LABELS[permission]} for ${ROLE_LABELS[role]}`}
                      onToggle={
                        lockReason
                          ? undefined
                          : () => onToggle(permission, role, !allowed)
                      }
                    />
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface PermissionCellProps {
  allowed: boolean;
  lockReason: LockReason;
  pending: boolean;
  label: string;
  onToggle?: () => void;
}

function PermissionCell({
  allowed,
  lockReason,
  pending,
  label,
  onToggle,
}: PermissionCellProps) {
  if (lockReason) {
    return (
      <span
        title={LOCK_TITLES[lockReason]}
        className={cn(
          'inline-flex h-7 w-7 items-center justify-center rounded-md border',
          allowed
            ? 'border-primary/20 bg-primary/10 text-primary'
            : 'border-border/[0.08] bg-foreground/[0.02] text-muted-soft',
        )}
        aria-label={`${label}: ${allowed ? 'allowed' : 'denied'} (locked)`}
      >
        {allowed ? <Check className="h-4 w-4" /> : <X className="h-4 w-4" />}
        <Lock className="ml-0.5 h-2.5 w-2.5 opacity-60" />
      </span>
    );
  }

  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={allowed}
      aria-label={label}
      disabled={pending}
      onClick={onToggle}
      className={cn(
        'inline-flex h-7 w-7 items-center justify-center rounded-md border transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50',
        allowed
          ? 'border-primary/40 bg-primary/20 text-primary hover:bg-primary/30'
          : 'border-border/[0.12] bg-foreground/[0.02] text-transparent hover:border-border/25',
        pending && 'cursor-wait opacity-60',
      )}
    >
      <Check className="h-4 w-4" />
    </button>
  );
}
