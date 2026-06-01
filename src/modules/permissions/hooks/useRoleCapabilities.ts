import { ROLE_CAPABILITIES } from '../constants/permissionsConstants';

// Thin hook so the page never imports constants directly — keeps the page
// agnostic about whether the source becomes a server-backed query later.
export function useRoleCapabilities() {
  return ROLE_CAPABILITIES;
}
