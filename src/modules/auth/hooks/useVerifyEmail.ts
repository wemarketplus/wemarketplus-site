import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { useVerifyEmailMutation } from '../api/authApi';
import { setCredentials } from '../store/authSlice';

export type VerifyEmailStatus = 'verifying' | 'failed';

// Consumes the ?token= from the verification email on mount. On success the
// backend returns a full auth session, so we store credentials and drop the
// new owner on /billing (the plan picker) to start their subscription.
export function useVerifyEmail(token: string | null) {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [verifyEmail] = useVerifyEmailMutation();
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
        navigate('/billing', { replace: true });
      } catch {
        setStatus('failed');
      }
    })();
  }, [dispatch, navigate, token, verifyEmail]);

  return { status };
}
