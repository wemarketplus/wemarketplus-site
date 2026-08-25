import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { Plus, TriangleAlert, UserCog } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { EntityRowActions } from '@/shared/ui/entity';
import { ROLE_LABELS } from '@/shared/rbac';
import { useCustomRoles } from '../hooks/useCustomRoles';
import { CustomRoleFormModal } from './CustomRoleFormModal';

/**
 * Admin → Manage Roles.
 *
 * TWO ENTRY POINTS, ONE COMPONENT. It renders under the permission matrix on
 * /permissions — same page rather than its own route because it is the same job
 * and the same audience: the matrix says what each role may DO, this says which
 * roles the tenant has and what each one SEES, and splitting them would mean an
 * admin configuring one role has to visit two screens to understand it. It also
 * renders as the CommunityLink "Manage roles" tab in Settings, because that
 * product's Administrator guide sends the reader there ("In Settings, look for
 * Manage Roles"). Both mount this; neither owns a copy.
 */
export function ManageCustomRoles() {
  const {
    roles,
    isLoading,
    needsUpgrade,
    forbidden,
    isError,
    refetch,
    catalog,
    selectableRoles,
    open,
    editing,
    draft,
    patchDraft,
    toggleKey,
    openCreate,
    openEdit,
    close,
    save,
    remove,
    isSaving,
  } = useCustomRoles();

  // Not an admin: the matrix above already says so, and repeating it here would be
  // two warnings about one thing.
  if (forbidden) return null;

  return (
    <section className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
            <UserCog className="h-5 w-5" />
          </div>
          <div>
            <h2 className={SECTION_TITLE}>
              Manage roles
            </h2>
            <p className="mt-1 max-w-2xl text-sm text-muted">
              Create a role for a job that none of the standard roles describes — an
              Activities Director, a Volunteer Coordinator, a part-time biller — and
              choose exactly which tabs it sees. Its permissions come from the role
              you base it on.
            </p>
          </div>
        </div>
        {!needsUpgrade && (
          <Button size="sm" onClick={openCreate}>
            <Plus className="h-4 w-4" />
            New role
          </Button>
        )}
      </header>

      {needsUpgrade ? (
        <Card>
          <CardContent className="flex flex-wrap items-center justify-between gap-3 px-6 py-5">
            <p className="text-sm text-muted">
              Custom roles are included with the Gold and Max plans.
            </p>
            <Link
              to="/billing"
              className="rounded-pill border border-border/[0.12] px-3 py-1.5 text-xs font-semibold text-foreground hover:border-primary/40 hover:text-primary"
            >
              View plans
            </Link>
          </CardContent>
        </Card>
      ) : isError ? (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/[0.06] py-10 text-center">
          <TriangleAlert className="h-6 w-6 text-destructive" />
          <p className="text-sm text-foreground">Could not load custom roles.</p>
          <Button variant="ghost" onClick={() => refetch()}>
            Retry
          </Button>
        </div>
      ) : isLoading ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-muted">
            Loading roles…
          </CardContent>
        </Card>
      ) : roles.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-muted">
            No custom roles yet. Everyone holds one of the standard roles.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {roles.map((role) => (
            <Card key={role.id}>
              <CardContent className="flex flex-wrap items-center gap-3 px-6 py-4">
                <div className="min-w-0 flex-1">
                  <p className="flex items-center gap-2 text-sm font-semibold text-foreground">
                    {role.name}
                    {!role.isActive && (
                      <span className="rounded-pill border border-border/[0.12] px-1.5 py-px text-[9px] font-black uppercase tracking-label text-muted-soft">
                        Disabled
                      </span>
                    )}
                  </p>
                  <p className="mt-0.5 text-xs text-muted-soft">
                    Permissions of {ROLE_LABELS[role.baseRole]} ·{' '}
                    {role.navKeys.length} tab
                    {role.navKeys.length === 1 ? '' : 's'} ·{' '}
                    {/* Member count is here because it decides whether deleting is
                        even possible — the API refuses while holders exist. */}
                    {role.memberCount ?? 0} user
                    {(role.memberCount ?? 0) === 1 ? '' : 's'}
                  </p>
                </div>
                <EntityRowActions
                  onEdit={() => openEdit(role)}
                  onDelete={() => remove(role)}
                />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <CustomRoleFormModal
        open={open}
        isEditing={editing !== null}
        isSaving={isSaving}
        draft={draft}
        catalog={catalog}
        selectableRoles={selectableRoles}
        onPatch={patchDraft}
        onToggleKey={toggleKey}
        onClose={close}
        onSave={save}
      />
    </section>
  );
}
