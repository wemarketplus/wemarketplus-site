import { toast } from 'sonner';
import { useOpenPortalSessionMutation } from '../api/billingApi';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';

export function useBillingPortal() {
  const [openPortal, { isLoading }] = useOpenPortalSessionMutation();

  const goToPortal = async () => {
    try {
      const { url } = await openPortal().unwrap();
      window.location.href = url;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, "Couldn't open billing portal"));
    }
  };

  return { goToPortal, isLoading };
}
