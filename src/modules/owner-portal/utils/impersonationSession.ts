import type { AuthenticatedUser } from '@/modules/auth/types/authTypes';

// The operator's own session, stashed while an impersonation session is active
// so "Exit" can restore it. Kept in localStorage (not redux-persist) so it
// survives the hard navigation into the impersonated workspace and any reload,
// independently of the auth slice that now holds the impersonation token.
const OPERATOR_SNAPSHOT_KEY = 'wmp-impersonation-operator';
const ACTIVE_BANNER_KEY = 'wmp-impersonation-active';

export interface OperatorSnapshot {
  token: string;
  refreshToken: string | null;
  user: AuthenticatedUser;
}

export interface ActiveImpersonation {
  tenantId: string;
  organizationName: string;
}

function safeParse<T>(raw: string | null): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function saveOperatorSnapshot(snapshot: OperatorSnapshot): void {
  localStorage.setItem(OPERATOR_SNAPSHOT_KEY, JSON.stringify(snapshot));
}

export function readOperatorSnapshot(): OperatorSnapshot | null {
  return safeParse<OperatorSnapshot>(localStorage.getItem(OPERATOR_SNAPSHOT_KEY));
}

export function markImpersonating(active: ActiveImpersonation): void {
  localStorage.setItem(ACTIVE_BANNER_KEY, JSON.stringify(active));
}

export function readActiveImpersonation(): ActiveImpersonation | null {
  return safeParse<ActiveImpersonation>(localStorage.getItem(ACTIVE_BANNER_KEY));
}

export function clearImpersonation(): void {
  localStorage.removeItem(OPERATOR_SNAPSHOT_KEY);
  localStorage.removeItem(ACTIVE_BANNER_KEY);
}
