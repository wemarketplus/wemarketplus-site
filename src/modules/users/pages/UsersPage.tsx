import { Plus } from 'lucide-react';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { RoleGate, STAFF_ROLES } from '@/shared/rbac';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { useUsersList } from '../hooks/useUsersList';
import { useAddUser } from '../hooks/useAddUser';
import { useEditUser } from '../hooks/useEditUser';
import { useDeleteUser } from '../hooks/useDeleteUser';
import { useUserRowActions } from '../hooks/useUserRowActions';
import { UsersFilters } from '../components/UsersFilters';
import { UsersTable } from '../components/UsersTable';
import { AddUserModal } from '../components/AddUserModal';
import { EditUserModal } from '../components/EditUserModal';
import { TempPasswordDialog } from '../components/TempPasswordDialog';

export function UsersPage() {
  const { users, total, page, lastPage, setPage, isLoading, isFetching, error } =
    useUsersList();
  const { open, isSaving, submitError, openModal, close, submit } = useAddUser();
  const edit = useEditUser();
  const { deleteUser, isDeleting } = useDeleteUser();
  const {
    reveal,
    dismissReveal,
    resetUserPassword,
    resendInvite,
    setUserActive,
    isBusy,
  } = useUserRowActions();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex flex-col gap-1">
          <h1 className="font-display text-3xl text-foreground">Team members</h1>
          <p className="text-sm text-muted">
            {total} {total === 1 ? 'user' : 'users'} across your CRM. Filter or search to
            narrow the list.
          </p>
        </div>
        <RoleGate allow={STAFF_ROLES}>
          <Button onClick={openModal}>
            <Plus className="h-4 w-4" /> Add user
          </Button>
        </RoleGate>
      </header>

      <Card>
        <CardContent className="space-y-5 pt-6">
          <UsersFilters />

          {error && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(error, 'Failed to load users')}
            </p>
          )}

          <UsersTable
            users={users}
            isLoading={isLoading}
            onEdit={edit.openEdit}
            onResetPassword={resetUserPassword}
            onResendInvite={resendInvite}
            onToggleActive={(u, next) => setUserActive(u, next)}
            onDelete={deleteUser}
            actionsDisabled={isBusy || isDeleting}
          />

          <div className="flex items-center justify-between text-xs text-muted-soft">
            <span className="uppercase tracking-[0.1em]">
              Page {page} of {lastPage}
              {isFetching && page > 1 ? ' · refreshing…' : ''}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="rounded-pill border border-border/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-border/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-border/[0.08] disabled:hover:text-muted"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
                disabled={page >= lastPage}
                className="rounded-pill border border-border/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-border/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-border/[0.08] disabled:hover:text-muted"
              >
                Next
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

      <AddUserModal
        open={open}
        isSaving={isSaving}
        submitError={submitError}
        onClose={close}
        onSubmit={submit}
      />

      <EditUserModal
        user={edit.editingUser}
        open={edit.open}
        isSaving={edit.isSaving}
        submitError={edit.submitError}
        onClose={edit.close}
        onSubmit={edit.submit}
      />

      <TempPasswordDialog reveal={reveal} onClose={dismissReveal} />
    </div>
  );
}
