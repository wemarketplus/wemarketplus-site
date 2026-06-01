import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { LoginResponse } from '@/modules/auth';
import type { OnboardRequest } from '../types/onboardingTypes';

// TODO(backend): ship POST /auth/onboard that accepts the full multi-step
// payload, creates the org + admin user, stores BAA signature, and returns
// the standard LoginResponse so the client can drop straight into the CRM.
export const onboardingApi = createApi({
  reducerPath: 'onboardingApi',
  baseQuery: baseQueryWithReauth,
  endpoints: (build) => ({
    onboard: build.mutation<LoginResponse, OnboardRequest>({
      query: (body) => ({ url: '/auth/onboard', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
    }),
  }),
});

export const { useOnboardMutation } = onboardingApi;
