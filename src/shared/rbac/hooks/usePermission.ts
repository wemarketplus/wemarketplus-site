import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { HL_VIEW_AS_ROLES } from '../constants/permissionsConstants';
import { Role } from '../types/permissionTypes';

interface RoleApi {
  /**
   * The role the UI should render for. This is the real role, UNLESS a management
   * user has switched "viewing as" to a field persona — then it is that persona.
   */
  role: Role | null;
  is: (role: Role) => boolean;
  isAny: (roles: readonly Role[]) => boolean;
  /** The role actually on the JWT. Never affected by the switcher. */
  actualRole: Role | null;
  /** The previewed persona, or null when viewing as yourself. */
  viewAsRole: Role | null;
  /** True while previewing — drives the "viewing as" banner. */
  isViewingAs: boolean;
  /** Whether this user is allowed to use the switcher at all. */
  canViewAs: boolean;
}

/**
 * Named `usePermission` to match the scaffold spec's filename, but the backend is
 * role-based so the returned API is role-shaped. See ../types/permissionTypes.
 *
 * THE "VIEWING AS" SWITCHER IS A PREVIEW, NOT PRIVILEGE. HospiceLink Gold is sold
 * as "4-role access" and had no role switcher at all, so a Nurse and an Admin saw
 * an identical sidebar. This hook is the single place the app resolves "which role
 * am I rendering for", so the switcher lives here rather than being threaded
 * through every component.
 *
 * Two invariants make it safe:
 *
 *   1. Only a management user may switch (`canViewAs`), and only INTO one of the
 *      three field personas (HL_VIEW_AS_ROLES). Previewing "up" into another
 *      management role is impossible — there is no value in it and it would be the
 *      shape of an escalation bug.
 *   2. Switching changes only what is RENDERED. Every request still carries the
 *      real role in its JWT, so a previewing Admin who types a hidden URL gets
 *      that route's real authorization answer from the server. The switcher can
 *      hide a screen; it can never unlock one, in either direction.
 */
export function usePermission(): RoleApi {
  const actualRole = useAppSelector((s) => s.auth.user?.role ?? null);
  const requestedViewAs = useAppSelector((s) => s.access.viewAsRole);

  return useMemo<RoleApi>(() => {
    // Management roles are the only ones offered the switcher. A Nurse cannot
    // "view as" anything — least of all a Marketer.
    const canViewAs =
      actualRole === Role.SuperAdmin ||
      actualRole === Role.Admin ||
      actualRole === Role.Owner ||
      actualRole === Role.Manager;

    // A stale persisted value (or a hand-edited store) must not take effect: the
    // requested role has to be both permitted for this user and in the allow-list.
    const viewAsRole =
      canViewAs && requestedViewAs && HL_VIEW_AS_ROLES.includes(requestedViewAs)
        ? requestedViewAs
        : null;

    const role = viewAsRole ?? actualRole;

    return {
      role,
      is: (target) => role === target,
      isAny: (targets) => (role ? targets.includes(role) : false),
      actualRole,
      viewAsRole,
      isViewingAs: viewAsRole !== null,
      canViewAs,
    };
  }, [actualRole, requestedViewAs]);
}

// Friendlier alias used throughout the app.
export const useRole = usePermission;
