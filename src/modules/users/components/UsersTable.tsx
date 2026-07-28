import { Role, ROLE_LABELS, STAFF_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { ROLE_PILL } from '../constants/usersConstants';
import type { UserRecord } from '../types/usersTypes';
import { fullName, initials } from '../utils/userDisplay';
import { UserRowActions } from './UserRowActions';

interface UsersTableProps {
  users: readonly UserRecord[];
  isLoading: boolean;
  // Row-action handlers are owned by the page (which holds the mutation hooks)
  // and passed down so the table stays presentational.
  onEdit: (user: UserRecord) => void;
  onResetPassword: (user: UserRecord) => void;
  onResendInvite: (user: UserRecord) => void;
  onToggleActive: (user: UserRecord, next: boolean) => void;
  onDelete: (user: UserRecord) => void;
  actionsDisabled: boolean;
}

export function UsersTable({
  users,
  isLoading,
  onEdit,
  onResetPassword,
  onResendInvite,
  onToggleActive,
  onDelete,
  actionsDisabled,
}: UsersTableProps) {
  const { role, isAny } = useRole();
  // Management roles may run the row actions (matches the page's Add-user gate
  // and the backend's manage_users permission on the mutations).
  const canManage = isAny(STAFF_ROLES);
  // Hard delete is SuperAdmin-only on the backend (DELETE /users/:id). The
  // earlier table gated the whole delete button on is('admin'), which never
  // matched a super admin and let a plain admin see it; align to the backend.
  const canDelete = role === Role.SuperAdmin;

  if (isLoading) {
    return (
      <div className="rounded-lg border border-border/[0.06] bg-surface p-10 text-center text-sm text-muted">
        Loading users…
      </div>
    );
  }

  const columns: ReadonlyArray<Column<UserRecord>> = [
    {
      key: 'user',
      header: 'User',
      cell: (u) => (
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[#dff1ff] text-xs font-semibold text-[#0f5c8a]">
            {initials(u)}
          </div>
          <div>
            <p className="font-bold text-foreground">{fullName(u)}</p>
            <p className="text-[11px] text-muted">{u.email}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      cell: (u) => <Pill tone={ROLE_PILL[u.role]}>{ROLE_LABELS[u.role]}</Pill>,
    },
    {
      key: 'status',
      header: 'Status',
      cell: (u) => (
        <Pill tone={u.isActive ? 'g' : 'r'}>{u.isActive ? 'Active' : 'Inactive'}</Pill>
      ),
    },
    { key: 'joined', header: 'Joined', cell: (u) => formatDate(u.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-12',
      className: 'text-right',
      cell: (u) =>
        canManage ? (
          <UserRowActions
            user={u}
            disabled={actionsDisabled}
            canDelete={canDelete}
            onEdit={onEdit}
            onResetPassword={onResetPassword}
            onResendInvite={onResendInvite}
            onToggleActive={onToggleActive}
            onDelete={onDelete}
          />
        ) : null,
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={users}
      rowKey={(u) => u.id}
      empty="No users match the current filters."
    />
  );
}
