import { Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { ROLE_LABELS, useRole } from '@/shared/rbac';
import { Role } from '@/shared/rbac/types/permissionTypes';
import { Button } from '@/shared/ui/core';
import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { useDeleteUserMutation } from '../api/usersApi';
import type { UserRecord } from '../types/usersTypes';
import { fullName, initials } from '../utils/userDisplay';

interface UsersTableProps {
  users: readonly UserRecord[];
  isLoading: boolean;
}

const ROLE_PILL: Record<Role, PillProps['tone']> = {
  [Role.Admin]: 'p',
  [Role.Manager]: 'b',
  [Role.Rep]: 'b',
};

export function UsersTable({ users, isLoading }: UsersTableProps) {
  const { is } = useRole();
  const [deleteUser, deleteState] = useDeleteUserMutation();

  const handleDelete = async (user: UserRecord) => {
    if (!window.confirm(`Delete ${fullName(user)}? This cannot be undone.`)) return;
    try {
      await deleteUser(user.id).unwrap();
      toast.success(`Deleted ${fullName(user)}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Failed to delete user'));
    }
  };

  if (isLoading) {
    return (
      <div className="rounded-lg border border-white/[0.06] bg-surface p-10 text-center text-sm text-muted">
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
            <p className="font-bold text-[#111]">{fullName(u)}</p>
            <p className="text-[11px] text-[#667]">{u.email}</p>
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      cell: (u) => <Pill tone={ROLE_PILL[u.role]}>{ROLE_LABELS[u.role]}</Pill>,
    },
    { key: 'joined', header: 'Joined', cell: (u) => formatDate(u.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-12',
      className: 'text-right',
      cell: (u) =>
        is('admin') ? (
          <Button
            variant="ghost"
            size="square"
            onClick={() => handleDelete(u)}
            disabled={deleteState.isLoading}
            aria-label={`Delete ${fullName(u)}`}
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
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
