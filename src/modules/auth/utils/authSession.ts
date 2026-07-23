import { toast } from 'sonner';
import type { NavigateFunction } from 'react-router-dom';
import type { AppDispatch } from '@/app/store';
import { clearPendingPlan, getPendingPlan } from '@/modules/onboarding';
import { setCredentials } from '../store/authSlice';
import type { AuthenticatedUser, LoginResponse } from '../types/authTypes';

type StartCheckoutHandler = (planKey: string) => Promise<void> | void;

export function commitAuthSession({
  dispatch,
  navigate,
  result,
  startCheckout,
  welcomeLabel = 'Welcome back',
}: {
  dispatch: AppDispatch;
  navigate: NavigateFunction;
  result: LoginResponse;
  startCheckout?: StartCheckoutHandler;
  welcomeLabel?: string;
}) {
  const user = result.user as AuthenticatedUser | undefined;
  if (!user) {
    toast.error('Authentication response was incomplete.');
    return;
  }

  dispatch(
    setCredentials({
      token: result.accessToken ?? null,
      refreshToken: result.refreshToken ?? null,
      user,
    }),
  );

  toast.success(`${welcomeLabel}, ${user.firstName}`);

  const pendingPlan = getPendingPlan();
  if (pendingPlan) {
    clearPendingPlan();
    if (startCheckout) {
      void startCheckout(pendingPlan);
      return;
    }
  }

  navigate('/', { replace: true });
}
