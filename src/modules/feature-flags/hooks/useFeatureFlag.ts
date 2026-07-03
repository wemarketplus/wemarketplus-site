import { useGetFeatureFlagsQuery } from '../api/featureFlagsApi';

interface FeatureFlagResult {
  /** True only once the flag is fetched AND enabled for the tenant. */
  isEnabled: boolean;
  isLoading: boolean;
}

/**
 * Reads GET /feature-flags and reports whether a single flag is on for the
 * current tenant. Fails closed: while loading, or for an unknown key, isEnabled
 * is false so gated UI stays hidden until the server confirms it is on.
 */
export function useFeatureFlag(key: string): FeatureFlagResult {
  const { data, isLoading } = useGetFeatureFlagsQuery();
  return {
    isEnabled: data?.[key] ?? false,
    isLoading,
  };
}
