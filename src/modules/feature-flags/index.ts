// Runtime feature flags: the SuperAdmin management screen, the useFeatureFlag
// hook that gates UI on GET /feature-flags, and the RTK Query api slice. These
// are operator-toggleable switches (rollouts / kill-switches), intentionally
// distinct from plan-tier gating (billing) — do not blur that boundary.
export { FeatureFlagsPage } from './pages/FeatureFlagsPage';
export { useFeatureFlag } from './hooks/useFeatureFlag';
export { default as featureFlagsReducer } from './store/featureFlagsSlice';
export {
  featureFlagsApi,
  useGetFeatureFlagsQuery,
  useListAdminFeatureFlagsQuery,
  useUpdateFeatureFlagMutation,
} from './api/featureFlagsApi';
