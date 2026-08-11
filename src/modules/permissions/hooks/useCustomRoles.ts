import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Role, type CustomRole } from '@/shared/rbac';
import {
  useCreateCustomRoleMutation,
  useDeleteCustomRoleMutation,
  useListCustomRolesQuery,
  useUpdateCustomRoleMutation,
} from '../api/permissionsApi';
import { buildNavCatalog } from '../utils/navCatalog';

export interface CustomRoleDraft {
  name: string;
  baseRole: Role;
  navKeys: string[];
  isActive: boolean;
}

const EMPTY_DRAFT: CustomRoleDraft = {
  name: '',
  // Caregiver is the NARROWEST field role, so a half-finished role starts from the
  // least permission rather than the most. An admin who forgets to change it has
  // created something harmless.
  baseRole: Role.Caregiver,
  navKeys: [],
  isActive: true,
};

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

  const [editing, setEditing] = useState<CustomRole | null>(null);
  const [draft, setDraft] = useState<CustomRoleDraft>(EMPTY_DRAFT);
  const [open, setOpen] = useState(false);

  const status =
    error && 'status' in error ? (error.status as number) : undefined;
  const needsUpgrade = status === 402;
  const forbidden = status === 403;

  // The checkbox catalogue follows the draft's base role — a custom role can only
  // narrow what that role already sees.
  const catalog = useMemo(() => buildNavCatalog(draft.baseRole), [draft.baseRole]);

  const openCreate = () => {
    setEditing(null);
    setDraft(EMPTY_DRAFT);
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
