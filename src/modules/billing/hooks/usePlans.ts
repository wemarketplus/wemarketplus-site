import { useGetPlansQuery } from '../api/billingApi';

// Reads the configured plan catalog (GET /billing/plans) for the tier picker.
export function usePlans() {
  const { data, isLoading } = useGetPlansQuery();
  return { plans: data ?? [], isLoading };
}
