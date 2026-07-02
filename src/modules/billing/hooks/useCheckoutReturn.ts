import { useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';
import { useConfirmCheckoutMutation } from '../api/billingApi';

// Handles the return from Stripe Checkout: reads the `?checkout=success|cancel`
// query param, then strips the params from the URL. On success it confirms the
// session server-side (POST /billing/checkout/confirm — the query param alone
// is never trusted) before showing the activation toast, and refetches the
// subscription either way so the page reflects whatever Stripe recorded.
export function useCheckoutReturn(onSuccess: () => void) {
  const [params, setParams] = useSearchParams();
  const [confirmCheckout] = useConfirmCheckoutMutation();
  // Checkout sessions are confirmed once — guard against StrictMode's double
  // effect run and re-renders that happen before setParams lands.
  const handledRef = useRef(false);

  useEffect(() => {
    const checkout = params.get('checkout');
    if (!checkout || handledRef.current) return;
    handledRef.current = true;
    const sessionId = params.get('session_id');

    if (checkout === 'success' && sessionId) {
      confirmCheckout({ sessionId })
        .unwrap()
        .then(() => {
          toast.success('Subscription activated — welcome aboard!');
        })
        .catch(() => {
          toast.error(
            "We couldn't confirm your payment yet — it may take a moment.",
          );
        })
        .finally(onSuccess);
    } else if (checkout === 'success') {
      // No session id to verify — fall back to the webhook-written state.
      toast.success('Subscription activated — welcome aboard!');
      onSuccess();
    } else if (checkout === 'cancel') {
      toast.message('Checkout canceled — no charge was made.');
    }

    params.delete('checkout');
    params.delete('session_id');
    setParams(params, { replace: true });
  }, [params, setParams, confirmCheckout, onSuccess]);
}
