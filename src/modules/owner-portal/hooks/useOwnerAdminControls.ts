import { toast } from 'sonner';
import { OWNER_ADMIN_CONTROLS } from '../constants/ownerScreenConstants';
import type { OwnerAdminControl } from '../types/ownerPortalTypes';

export function useOwnerAdminControls() {
  const runControl = (control: OwnerAdminControl) =>
    toast.message(`${control.title} — backend not wired`);
  return { controls: OWNER_ADMIN_CONTROLS, runControl };
}
