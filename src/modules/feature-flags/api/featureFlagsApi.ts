import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  EffectiveFlags,
  FeatureFlag,
  UpdateFeatureFlagRequest,
} from '../types/featureFlagsApiTypes';

// Runtime feature flags — wemarketplus-backend/src/feature-flags.
export const featureFlagsApi = createApi({
  reducerPath: 'featureFlagsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['FeatureFlags', 'AdminFeatureFlags'],
  endpoints: (build) => ({
    // Effective flags for the caller's tenant. Read by the useFeatureFlag hook
    // to gate UI. Any authenticated user may fetch these.
    getFeatureFlags: build.query<EffectiveFlags, void>({
      query: () => ({ url: '/feature-flags' }),
      transformResponse: (res: ApiEnvelope<EffectiveFlags>) => res.data,
      providesTags: ['FeatureFlags'],
    }),
    // SuperAdmin-only management list (full records incl. overrides).
    listAdminFeatureFlags: build.query<FeatureFlag[], void>({
      query: () => ({ url: '/admin/feature-flags' }),
      transformResponse: (res: ApiEnvelope<FeatureFlag[]>) => res.data,
      providesTags: ['AdminFeatureFlags'],
    }),
    updateFeatureFlag: build.mutation<FeatureFlag, UpdateFeatureFlagRequest>({
      query: ({ key, ...body }) => ({
        url: `/admin/feature-flags/${key}`,
        method: 'PUT',
        body,
      }),
      transformResponse: (res: ApiEnvelope<FeatureFlag>) => res.data,
      // Refresh both the admin view and any tenant's effective flags so a
      // toggle reflects immediately on gated UI.
      invalidatesTags: ['AdminFeatureFlags', 'FeatureFlags'],
    }),
  }),
});

export const {
  useGetFeatureFlagsQuery,
  useListAdminFeatureFlagsQuery,
  useUpdateFeatureFlagMutation,
} = featureFlagsApi;
