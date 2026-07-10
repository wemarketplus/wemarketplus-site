import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { useStartCheckout } from '@/modules/billing/hooks/useStartCheckout';
import { clearPendingPlan, getPendingPlan } from '@/modules/onboarding';
import { useVerifyEmailMutation } from '../api/authApi';
import { setCredentials } from '../store/authSlice';

export type VerifyEmailStatus = 'verifying' | 'failed';

// Consumes the ?token= from the verification email on mount. On success the
// backend returns a full auth session and stores credentials. If the visitor
// picked a plan on the pricing page (persisted through the funnel), we send
// them straight to Stripe Checkout for that plan; otherwise we drop the new
// owner on /billing (the plan picker) to choose a subscription.
export function useVerifyEmail(token: string | null) {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [verifyEmail] = useVerifyEmailMutation();
  const { startCheckout } = useStartCheckout();
  const [status, setStatus] = useState<VerifyEmailStatus>('verifying');
  // Tokens are single-use — guard against StrictMode's double effect run so
  // the second call doesn't 401 a token the first call just consumed.
  const firedRef = useRef(false);

  useEffect(() => {
    if (!token || firedRef.current) return;
    firedRef.current = true;
    void (async () => {
      try {
        const result = await verifyEmail({ token }).unwrap();
        dispatch(
          setCredentials({
            token: result.accessToken ?? null,
            refreshToken: result.refreshToken ?? null,
            user: result.user,
          }),
        );
        toast.success('Email verified — welcome aboard!');
        // If a plan was chosen in the pricing funnel, go straight to Stripe
        // Checkout for it (startCheckout redirects the browser). Clear the
        // stored choice first so a later plan-less signup can't inherit it.
        const pendingPlan = getPendingPlan();
        if (pendingPlan) {
          clearPendingPlan();
          void startCheckout(pendingPlan);
          return;
        }
        navigate('/billing', { replace: true });
      } catch {
        setStatus('failed');
      }
    })();
  }, [dispatch, navigate, startCheckout, token, verifyEmail]);

  return { status };
}
