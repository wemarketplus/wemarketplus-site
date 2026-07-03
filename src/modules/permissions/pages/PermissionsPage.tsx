import { Info, Loader2, ShieldCheck, TriangleAlert } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { PermissionMatrixGrid } from '../components/PermissionMatrixGrid';
import { usePermissionMatrix } from '../hooks/usePermissionMatrix';

export function PermissionsPage() {
  const {
    view,
    isLoading,
    isError,
    errorMessage,
    refetch,
    canEdit,
    pendingCell,
    toggle,
  } = usePermissionMatrix();

  return (
    <div className="space-y-8">
      <header className="flex items-start gap-4">
        <div className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <h1 className="font-display text-3xl leading-tight text-foreground">
            Roles &amp; permissions
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">
            This matrix is the live, enforced RBAC policy. The backend checks every
            request against it via{' '}
            <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-xs text-foreground">
              @RequirePermission()
            </code>{' '}
            guards. Toggle a cell to grant or revoke a capability for a role.
          </p>
        </div>
      </header>

      {!canEdit && (
        <div className="flex items-start gap-3 rounded-lg border border-white/[0.08] bg-white/[0.02] px-4 py-3 text-sm text-muted">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-muted-soft" />
          <p>Only a Super Admin can edit permissions. This matrix is read-only for you.</p>
        </div>
      )}

      {isLoading && (
        <div className="flex items-center justify-center gap-2 rounded-lg border border-white/[0.08] py-16 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading permissions…
        </div>
      )}

      {isError && !isLoading && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/[0.06] py-12 text-center">
          <TriangleAlert className="h-6 w-6 text-destructive" />
          <p className="text-sm text-foreground">{errorMessage}</p>
          <Button variant="ghost" onClick={() => refetch()}>
            Retry
          </Button>
        </div>
      )}

      {!isLoading && !isError && view && (
        <PermissionMatrixGrid
          permissions={view.permissions}
          locked={view.locked}
          canEdit={canEdit}
          pendingCell={pendingCell}
          onToggle={toggle}
        />
      )}
    </div>
  );
}
