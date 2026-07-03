import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '../utils/errorUtils';
import {
  useMfaDisableMutation,
  useMfaEnableMutation,
  useMfaSetupMutation,
} from '../api/authApi';
import type { MfaSetupResponse } from '../types/authTypes';

// Drives the Security tab's two-factor enable/disable flows. Enable is a
// two-phase enrolment (setup -> confirm a code); disable verifies a code or
// the account password. The caller (SecurityTab) owns the modal UI; this hook
// owns the API calls, the pending setup payload, and toasts.
export function useMfaManagement() {
  const [setup, setupState] = useMfaSetupMutation();
  const [enable, enableState] = useMfaEnableMutation();
  const [disable, disableState] = useMfaDisableMutation();
  // The pending enrolment payload (QR + secret) shown while confirming a code.
  const [pendingSetup, setPendingSetup] = useState<MfaSetupResponse | null>(null);

  // Phase 1: generate a secret + QR to display in the enable modal.
  const startSetup = useCallback(async (): Promise<boolean> => {
    try {
      const result = await setup().unwrap();
      setPendingSetup(result);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, "Couldn't start MFA setup"));
      return false;
    }
  }, [setup]);

  // Phase 2: confirm the pending secret with a live code.
  const confirmEnable = useCallback(
    async (code: string): Promise<boolean> => {
      try {
        await enable({ code }).unwrap();
        setPendingSetup(null);
        toast.success('Two-factor authentication enabled');
        return true;
      } catch (err) {
        toast.error(extractApiErrorMessage(err, 'Invalid authentication code'));
        return false;
      }
    },
    [enable],
  );

  // Disable via a live code OR the account password.
  const disableMfa = useCallback(
    async (proof: { code?: string; password?: string }): Promise<boolean> => {
      try {
        await disable(proof).unwrap();
        toast.success('Two-factor authentication disabled');
        return true;
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't disable MFA"));
        return false;
      }
    },
    [disable],
  );

  const clearSetup = useCallback(() => setPendingSetup(null), []);

  return {
    startSetup,
    confirmEnable,
    disableMfa,
    pendingSetup,
    clearSetup,
    isStartingSetup: setupState.isLoading,
    isEnabling: enableState.isLoading,
    isDisabling: disableState.isLoading,
  };
}
