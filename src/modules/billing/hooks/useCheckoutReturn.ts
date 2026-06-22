import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';

// Handles the return from Stripe Checkout: reads the `?checkout=success|cancel`
// query param, shows the matching toast, triggers a refetch on success (the
// webhook has written the subscription), then strips the params from the URL.
export function useCheckoutReturn(onSuccess: () => void) {
  const [params, setParams] = useSearchParams();

  useEffect(() => {
    const checkout = params.get('checkout');
    if (!checkout) return;
    if (checkout === 'success') {
      toast.success('Subscription activated — welcome aboard!');
      onSuccess();
    } else if (checkout === 'cancel') {
      toast.message('Checkout canceled — no charge was made.');
    }
    params.delete('checkout');
    params.delete('session_id');
    setParams(params, { replace: true });
  }, [params, setParams, onSuccess]);
}
