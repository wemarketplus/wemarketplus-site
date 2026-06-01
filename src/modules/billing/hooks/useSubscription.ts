import { useGetSubscriptionQuery } from '../api/billingApi';
import { SUBSCRIPTION_FIXTURE } from '@/shared/fixtures';
import type { SubscriptionRecord } from '../types/billingTypes';

// Wraps the RTK Query subscription read with a fixture fallback so screens
// render with realistic data before the backend ships /subscription-status.
// When the backend lands, the fixture branch becomes dead — delete it.
export function useSubscription(): {
  data: SubscriptionRecord;
  isLoading: boolean;
  isUsingFixture: boolean;
} {
  const { data, isLoading } = useGetSubscriptionQuery();
  if (data) return { data, isLoading: false, isUsingFixture: false };
  return {
    data: SUBSCRIPTION_FIXTURE as SubscriptionRecord,
    isLoading,
    isUsingFixture: true,
  };
}
