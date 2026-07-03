import { useCallback } from 'react';
import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setCredentials } from '@/modules/auth/store/authSlice';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useStartImpersonationMutation,
  useStopImpersonationMutation,
} from '../api/impersonationApi';
import {
  clearImpersonation,
  markImpersonating,
  readOperatorSnapshot,
  saveOperatorSnapshot,
} from '../utils/impersonationSession';

/**
 * Drives SuperAdmin tenant impersonation on the client. `start` preserves the
 * operator's own session, swaps in the impersonation token as the active
 * session, and returns true so the caller can navigate into the workspace.
 * `stop` calls the audit endpoint and restores the operator's session.
 */
export function useImpersonation() {
  const dispatch = useAppDispatch();
  const operator = useAppSelector((s) => s.auth.user);
  const token = useAppSelector((s) => s.auth.token);
  const refreshToken = useAppSelector((s) => s.auth.refreshToken);
  const [startImpersonation, { isLoading: isStarting }] =
    useStartImpersonationMutation();
  const [stopImpersonation, { isLoading: isStopping }] =
    useStopImpersonationMutation();

  const start = useCallback(
    async (tenantId: string): Promise<boolean> => {
      // Snapshot the operator's session BEFORE swapping, so Exit can restore it.
      if (token && operator) {
        saveOperatorSnapshot({ token, refreshToken, user: operator });
      }
      try {
        const session = await startImpersonation(tenantId).unwrap();
        markImpersonating({
          tenantId: session.tenantId,
          organizationName: session.organizationName,
        });
        dispatch(
          setCredentials({
            token: session.accessToken,
            refreshToken: session.refreshToken ?? null,
            user: session.user,
          }),
        );
        return true;
      } catch (err) {
        clearImpersonation();
        toast.error(
          extractApiErrorMessage(err, 'Could not start impersonation.'),
        );
        return false;
      }
    },
    [dispatch, operator, refreshToken, startImpersonation, token],
  );

  const stop = useCallback(async (): Promise<void> => {
    // Best-effort audit; the session is restored regardless of the call result.
    try {
      await stopImpersonation().unwrap();
    } catch {
      // Ignore: the operator must be able to exit even if the audit write fails.
    }
    const snapshot = readOperatorSnapshot();
    clearImpersonation();
    if (snapshot) {
      dispatch(
        setCredentials({
          token: snapshot.token,
          refreshToken: snapshot.refreshToken,
          user: snapshot.user,
        }),
      );
    }
  }, [dispatch, stopImpersonation]);

  return { start, stop, isStarting, isStopping };
}
