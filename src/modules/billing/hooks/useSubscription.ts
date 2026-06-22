import { useAppSelector } from '@/app/hooks';
import { SUBSCRIPTION_FIXTURE } from '@/shared/fixtures';
import { Product } from '@/shared/types';
import { useGetSubscriptionQuery } from '../api/billingApi';
import type { SubscriptionView } from '../types/billingTypes';
import { toSubscriptionView } from '../utils/billingUtils';

// Wraps the RTK Query subscription read. The backend returns 404 (no row) until
// a tenant actually subscribes via Stripe, so we distinguish three states:
//   - loading:          query in flight
//   - hasSubscription:  real backend data — render the live plan/status
//   - no subscription:  honest empty state (NOT the fixture as if it were real)
// `data` still falls back to the fixture so the populated layout has shape to
// render, but callers should gate on `hasSubscription` before trusting status.
// `refetch` re-reads after Stripe Checkout so the new subscription shows up.
export function useSubscription(): {
  data: SubscriptionView;
  isLoading: boolean;
  hasSubscription: boolean;
  refetch: () => void;
} {
  const { data, isLoading, refetch } = useGetSubscriptionQuery();
  const user = useAppSelector((s) => s.auth.user);

  if (data) {
    const product = user?.product ?? Product.HospiceLink;
    const organizationName = SUBSCRIPTION_FIXTURE.organizationName;
    return {
      data: toSubscriptionView(data, product, organizationName),
      isLoading: false,
      hasSubscription: true,
      refetch,
    };
  }

  return {
    data: SUBSCRIPTION_FIXTURE as SubscriptionView,
    isLoading,
    hasSubscription: false,
    refetch,
  };
}
