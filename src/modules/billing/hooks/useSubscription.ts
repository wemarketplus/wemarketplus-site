import { useAppSelector } from '@/app/hooks';
import { Product, SubscriptionStatus, Tier } from '@/shared/types';
import { useGetSubscriptionQuery } from '../api/billingApi';
import type { SubscriptionView } from '../types/billingTypes';
import { toSubscriptionView } from '../utils/billingUtils';

// Wraps the RTK Query subscription read. The backend returns 404 (no row) until
// a tenant actually subscribes via Stripe, so we distinguish three states:
//   - loading:          query in flight
//   - hasSubscription:  real backend data — render the live plan/status
//   - no subscription:  a neutral empty view (status "canceled", no fabricated
//                       plan) so callers gating on `hasSubscription` render an
//                       honest "no active plan" state.
// `refetch` re-reads after Stripe Checkout so the new subscription shows up.
export function useSubscription(): {
  data: SubscriptionView;
  isLoading: boolean;
  hasSubscription: boolean;
  refetch: () => void;
} {
  const { data, isLoading, refetch } = useGetSubscriptionQuery();
  const user = useAppSelector((s) => s.auth.user);
  const product = user?.product ?? Product.HospiceLink;
  const organizationName = user?.organizationName ?? 'Your organization';

  if (data) {
    return {
      data: toSubscriptionView(data, product, organizationName),
      isLoading: false,
      hasSubscription: true,
      refetch,
    };
  }

  // No subscription on file — neutral shape, never a fabricated active plan.
  return {
    data: {
      product,
      plan: Tier.Pro,
      status: SubscriptionStatus.Canceled,
      currentPeriodEnd: '',
      organizationName,
    },
    isLoading,
    hasSubscription: false,
    refetch,
  };
}
