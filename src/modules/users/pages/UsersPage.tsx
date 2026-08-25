import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { Plus } from 'lucide-react';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useActiveEntitlement } from '@/modules/access';
import { ADMIN_ONLY, RoleGate, STAFF_ROLES } from '@/shared/rbac';
import { Product } from '@/shared/types';
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
import { TeamOverviewStats } from '../components/TeamOverviewStats';

export function UsersPage() {
  const { users, total, page, lastPage, setPage, isLoading, isFetching, error } =
    useUsersList();
  const { open, isSaving, submitError, openModal, close, submit } = useAddUser();
  // HospiceLink reaches this screen from a nav item called "Admin" (its product
  // guide says "Click Admin in the left menu"), so the heading matches what the
  // reader clicked. CommunityLink still calls it Team.
  const { product } = useActiveEntitlement();
  const isHospiceLink = product === Product.HospiceLink;
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
          <h1 className={PAGE_TITLE}>
            {isHospiceLink ? 'Admin' : 'Team members'}
          </h1>
          <p className="text-sm text-muted">
            {total} {total === 1 ? 'user' : 'users'} across your CRM. Filter or search to
            narrow the list.
          </p>
        </div>
        <RoleGate allow={STAFF_ROLES}>
          <Button onClick={openModal}>
            <Plus className="h-4 w-4" />{' '}
            {isHospiceLink ? 'Invite team member' : 'Add user'}
          </Button>
        </RoleGate>
      </header>

      {/*
        Admin / Office Manager only. Both endpoints behind this band are
        Admin/Owner-gated server-side, so the RoleGate is what stops a Manager —
        who may legitimately read the list below — from firing two 403s.
      */}
      <RoleGate allow={ADMIN_ONLY}>
        <TeamOverviewStats />
      </RoleGate>

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
            <span className="uppercase tracking-label">
              Page {page} of {lastPage}
              {isFetching && page > 1 ? ' · refreshing…' : ''}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="rounded-pill border border-border/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-label text-muted transition-colors hover:border-border/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-border/[0.08] disabled:hover:text-muted"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
                disabled={page >= lastPage}
                className="rounded-pill border border-border/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-label text-muted transition-colors hover:border-border/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-border/[0.08] disabled:hover:text-muted"
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
