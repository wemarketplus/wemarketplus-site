import { Button, Input, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { ROLE_LABELS, Role, ALL_ROLES } from '@/shared/rbac';
import type { CustomRoleDraft } from '../hooks/useCustomRoles';
import type { NavCatalogGroup } from '../utils/navCatalog';

interface CustomRoleFormModalProps {
  open: boolean;
  isEditing: boolean;
  isSaving: boolean;
  draft: CustomRoleDraft;
  catalog: NavCatalogGroup[];
  onPatch: (patch: Partial<CustomRoleDraft>) => void;
  onToggleKey: (key: string) => void;
  onClose: () => void;
  onSave: () => void;
}

/**
 * Create/edit a custom role: a name, the role it inherits permissions from, and the
 * tabs it shows.
 *
 * `baseRole` is presented as "Permissions of" rather than "Role", because that is
 * exactly what it does — the tab checkboxes decide the MENU, this decides what the
 * holder is allowed to do. Conflating the two is how an admin would accidentally give
 * a volunteer coordinator administrator rights by picking the role whose tab list
 * looked closest.
 *
 * Super Admin is absent from the picker: it is the platform-staff role, and the
 * backend rejects it too (CUSTOM_ROLE_BASE_ROLES).
 */
export function CustomRoleFormModal({
  open,
  isEditing,
  isSaving,
  draft,
  catalog,
  onPatch,
  onToggleKey,
  onClose,
  onSave,
}: CustomRoleFormModalProps) {
  const selectableRoles = ALL_ROLES.filter((role) => role !== Role.SuperAdmin);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEditing ? 'Edit custom role' : 'New custom role'}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={onSave} disabled={isSaving}>
            {isSaving ? 'Saving…' : isEditing ? 'Save role' : 'Create role'}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <Label htmlFor="cr-name">Role name</Label>
            <Input
              id="cr-name"
              value={draft.name}
              maxLength={60}
              placeholder="Volunteer Coordinator"
              onChange={(e) => onPatch({ name: e.target.value })}
            />
          </div>
          <div>
            <Label htmlFor="cr-base">Permissions of</Label>
            <Select
              id="cr-base"
              value={draft.baseRole}
              onChange={(e) =>
                // Changing the base role re-filters the tab catalogue, so drop any
                // now-unavailable keys instead of silently storing dead ones.
                onPatch({ baseRole: e.target.value as Role, navKeys: [] })
              }
            >
              {selectableRoles.map((role) => (
                <option key={role} value={role}>
                  {ROLE_LABELS[role]}
                </option>
              ))}
            </Select>
            <p className="mt-1 text-[11px] leading-snug text-muted-soft">
              What this role may DO. The tabs below only decide what it SEES —
              unchecking a tab hides it, it does not remove the permission.
            </p>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between">
            <Label>Visible tabs ({draft.navKeys.length} selected)</Label>
            {draft.navKeys.length > 0 && (
              <button
                type="button"
                className="text-[11px] font-semibold text-primary hover:underline"
                onClick={() => onPatch({ navKeys: [] })}
              >
                Clear all
              </button>
            )}
          </div>
          {/* Scrolls inside its own box: the catalogue is long, and a modal that
              grows past the viewport hides its own save button. */}
          <div className="mt-2 max-h-[45vh] space-y-4 overflow-y-auto rounded-lg border border-border/[0.08] p-4">
            {catalog.length === 0 ? (
              <p className="text-sm text-muted">
                The selected role has no tabs of its own to choose from.
              </p>
            ) : (
              catalog.map((group) => (
                <fieldset key={group.title}>
                  <legend className="mb-1 text-[10px] font-black uppercase tracking-[0.12em] text-muted-soft">
                    {group.title}
                  </legend>
                  <div className="grid gap-1 sm:grid-cols-2">
                    {group.entries.map((entry) => (
                      <label
                        key={entry.key}
                        className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[13px] text-foreground hover:bg-foreground/[0.04]"
                      >
                        <input
                          type="checkbox"
                          className="h-3.5 w-3.5 shrink-0 accent-current"
                          checked={draft.navKeys.includes(entry.key)}
                          onChange={() => onToggleKey(entry.key)}
                        />
                        <span className="truncate">{entry.label}</span>
                      </label>
                    ))}
                  </div>
                </fieldset>
              ))
            )}
          </div>
        </div>

        <label className="flex cursor-pointer items-center gap-2 text-[13px] text-foreground">
          <input
            type="checkbox"
            className="h-3.5 w-3.5 accent-current"
            checked={draft.isActive}
            onChange={(e) => onPatch({ isActive: e.target.checked })}
          />
          {/* Disabling is the safe alternative to deleting: holders keep their
              accounts and fall back to their base role's normal menu. */}
          Active — available to assign to staff
        </label>
      </div>
    </Modal>
  );
}
