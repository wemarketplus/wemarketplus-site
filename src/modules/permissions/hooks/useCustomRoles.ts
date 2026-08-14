import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { useAppSelector } from '@/app/hooks';
import { entitledProducts, useActiveProduct } from '@/modules/access';
import { ALL_ROLES, Role, type CustomRole } from '@/shared/rbac';
import {
  useCreateCustomRoleMutation,
  useDeleteCustomRoleMutation,
  useListCustomRolesQuery,
  useUpdateCustomRoleMutation,
} from '../api/permissionsApi';
import { DEFAULT_CUSTOM_ROLE_BASE } from '../constants/customRolesConstants';
import { buildNavCatalog, isRoleUsedByProducts } from '../utils/navCatalog';

export interface CustomRoleDraft {
  name: string;
  baseRole: Role;
  navKeys: string[];
  isActive: boolean;
}

/**
 * Admin → Manage Roles: the tenant's own job titles and the tabs each one shows.
 *
 * `isUnavailable` distinguishes the two ways this screen can be unusable, because
 * they need different words: 402 means the plan does not include custom roles (the
 * guide sells them at Gold/Max), 403 means this user is not an admin. Anything else
 * is a real error worth a retry button.
 */
export function useCustomRoles() {
  const { data, isLoading, error, refetch } = useListCustomRolesQuery();
  const [createRole, createState] = useCreateCustomRoleMutation();
  const [updateRole, updateState] = useUpdateCustomRoleMutation();
  const [deleteRole] = useDeleteCustomRoleMutation();

  /**
   * A blank role, based on the narrowest persona of the dashboard the admin is
   * standing in — so "save without touching the base role" is both harmless AND
   * usable. See DEFAULT_CUSTOM_ROLE_BASE for why one shared default was neither.
   */
  const { activeProduct } = useActiveProduct();
  const emptyDraft = useMemo<CustomRoleDraft>(
    () => ({
      name: '',
      baseRole: DEFAULT_CUSTOM_ROLE_BASE[activeProduct],
      navKeys: [],
      isActive: true,
    }),
    [activeProduct],
  );

  const [editing, setEditing] = useState<CustomRole | null>(null);
  const [draft, setDraft] = useState<CustomRoleDraft>(emptyDraft);
  const [open, setOpen] = useState(false);

  const status =
    error && 'status' in error ? (error.status as number) : undefined;
  const needsUpgrade = status === 402;
  const forbidden = status === 403;

  /**
   * The checkbox catalogue follows the draft's base role — a custom role can only
   * narrow what that role already sees — and is limited to the dashboards the
   * tenant actually pays for. Read off the store user rather than `useEntitlements`
   * so the memo has a stable dependency: that hook builds a fresh array per render,
   * which would rebuild the catalogue on every keystroke in the name field.
   */
  const user = useAppSelector((s) => s.auth.user);
  const products = useMemo(() => entitledProducts(user), [user]);
  const catalog = useMemo(
    () => buildNavCatalog(draft.baseRole, products),
    [draft.baseRole, products],
  );

  /**
   * The base roles worth offering: the ones that actually have tabs on a dashboard
   * this tenant holds. Super Admin is absent because it is the platform-staff role
   * and the backend rejects it too (CUSTOM_ROLE_BASE_ROLES); the rest drop out per
   * tenant — a CommunityLink-only community has no use for Nurse, Caregiver or
   * Sales Rep, and picking one would leave the admin staring at an empty checkbox
   * list with no indication of what they did wrong.
   *
   * THE DRAFT'S OWN BASE ROLE IS ALWAYS INCLUDED, even when it would otherwise be
   * filtered out. Roles created before this filter existed can be based on a role
   * that no longer qualifies — a CommunityLink tenant really does have a
   * Caregiver-based "Volunteer Coordinator" on file — and a <select> whose value is
   * absent from its options renders as the FIRST option instead. Opening such a
   * role to rename it would silently re-base it on save.
   */
  const selectableRoles = useMemo(
    () =>
      ALL_ROLES.filter(
        (role) =>
          role !== Role.SuperAdmin &&
          (role === draft.baseRole || isRoleUsedByProducts(role, products)),
      ),
    [products, draft.baseRole],
  );

  const openCreate = () => {
    setEditing(null);
    setDraft(emptyDraft);
    setOpen(true);
  };

  const openEdit = (role: CustomRole) => {
    setEditing(role);
    setDraft({
      name: role.name,
      baseRole: role.baseRole,
      navKeys: [...role.navKeys],
      isActive: role.isActive,
    });
    setOpen(true);
  };

  const close = () => {
    setOpen(false);
    setEditing(null);
  };

  const patchDraft = (patch: Partial<CustomRoleDraft>) =>
    setDraft((current) => ({ ...current, ...patch }));

  const toggleKey = (key: string) =>
    setDraft((current) => ({
      ...current,
      navKeys: current.navKeys.includes(key)
        ? current.navKeys.filter((k) => k !== key)
        : [...current.navKeys, key],
    }));

  const save = async (): Promise<boolean> => {
    if (draft.name.trim().length < 2) {
      toast.error('Give the role a name');
      return false;
    }
    if (draft.navKeys.length === 0) {
      // Mirrors the backend's ArrayNotEmpty so the user is told before the round
      // trip rather than by a 400.
      toast.error('Choose at least one tab this role can see');
      return false;
    }
    const body = {
      name: draft.name.trim(),
      baseRole: draft.baseRole,
      navKeys: draft.navKeys,
      isActive: draft.isActive,
    };
    try {
      if (editing) {
        await updateRole({ id: editing.id, patch: body }).unwrap();
        toast.success(`Updated ${body.name}`);
      } else {
        await createRole(body).unwrap();
        toast.success(`Created ${body.name}`);
      }
      close();
      return true;
    } catch (e) {
      const message =
        e && typeof e === 'object' && 'data' in e
          ? ((e.data as { message?: string })?.message ??
            'Could not save the role')
          : 'Could not save the role';
      toast.error(message);
      return false;
    }
  };

  const remove = async (role: CustomRole) => {
    try {
      await deleteRole(role.id).unwrap();
      toast.success(`Deleted ${role.name}`);
    } catch (e) {
      // The 409 here is informative, not a failure to paper over: it names how many
      // people still hold the role.
      const message =
        e && typeof e === 'object' && 'data' in e
          ? ((e.data as { message?: string })?.message ??
            'Could not delete the role')
          : 'Could not delete the role';
      toast.error(message);
    }
  };

  return {
    roles: data ?? [],
    isLoading,
    needsUpgrade,
    forbidden,
    isError: Boolean(error) && !needsUpgrade && !forbidden,
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
    isSaving: createState.isLoading || updateState.isLoading,
  };
}
