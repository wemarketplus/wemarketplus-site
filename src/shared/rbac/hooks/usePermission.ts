import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { Role } from '../types/permissionTypes';

interface RoleApi {
  /**
   * The role the UI renders for. Always the role on the JWT — see the note below
   * on why there is no longer a second answer to this question.
   */
  role: Role | null;
  is: (role: Role) => boolean;
  isAny: (roles: readonly Role[]) => boolean;
  /**
   * The role on the JWT. Identical to `role`, kept as a distinct name because call
   * sites read better saying which one they mean, and because it is the field that
   * would stay honest if a render-only preview ever returns.
   */
  actualRole: Role | null;
}

/**
 * Named `usePermission` to match the scaffold spec's filename, but the backend is
 * role-based so the returned API is role-shaped. See ../types/permissionTypes.
 *
 * ONE ROLE, ALWAYS THE REAL ONE. This hook used to resolve a "viewing as" preview —
 * a management user could render the app as a lesser persona — and the sidebar
 * offered the other roles as buttons. That is gone: the "Viewing as" row now
 * reports the signed-in role and nothing else (see ViewingAsBadge).
 *
 * The preview machinery was removed rather than left dormant, deliberately. Its
 * value lived in `access.viewAsRole`, which is PERSISTED; with no control left to
 * clear it, a stale value would have kept narrowing someone's navigation with no
 * way out — and a code path that changes which role the UI renders for, reachable
 * only by hand-editing storage, is the shape of an escalation bug even when it can
 * only ever hide things. Nothing reads that field any more.
 *
 * What never changed, and is why the preview was safe while it existed: rendering
 * has never been authorization. Every request carries the real role in its JWT and
 * the server answers on that alone, so this hook can hide a screen and could never
 * unlock one.
 */
export function usePermission(): RoleApi {
  const actualRole = useAppSelector((s) => s.auth.user?.role ?? null);

  return useMemo<RoleApi>(
    () => ({
      role: actualRole,
      is: (target) => actualRole === target,
      isAny: (targets) => (actualRole ? targets.includes(actualRole) : false),
      actualRole,
    }),
    [actualRole],
  );
}

// Friendlier alias used throughout the app.
export const useRole = usePermission;
