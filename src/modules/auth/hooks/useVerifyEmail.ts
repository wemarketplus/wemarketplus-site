import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useVerifyEmailMutation } from '../api/authApi';
import { AUTH_REDIRECT_DELAY_MS } from '../constants/authConstants';

export type VerifyEmailStatus = 'verifying' | 'verified' | 'failed';

// Consumes the ?token= from the verification email on mount. This only marks
// the address verified — it does NOT log the user in (the backend issues no
// tokens). Per OWASP, the user then signs in through the normal login flow, so
// on success we forward to /login. Any plan chosen in the pricing funnel stays
// in localStorage and is honoured by the login flow after they sign in.
export function useVerifyEmail(token: string | null) {
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
        await verifyEmail({ token }).unwrap();
        setStatus('verified');
        toast.success('Email verified. Please sign in to continue.');
        setTimeout(() => navigate('/login', { replace: true }), AUTH_REDIRECT_DELAY_MS);
      } catch {
        setStatus('failed');
      }
    })();
  }, [navigate, token, verifyEmail]);

  return { status };
}
