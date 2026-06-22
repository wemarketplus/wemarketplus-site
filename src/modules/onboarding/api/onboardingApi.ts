import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { LoginResponse } from '@/modules/auth';
import type { OnboardRequest } from '../types/onboardingTypes';

// There is no single /auth/onboard endpoint. The wizard is composed from real
// backend calls (all under /api):
//   1. POST /auth/register  { email, password, firstName, lastName, organizationName }
//        -> AuthResponseDto { accessToken, refreshToken?, user }
//   2. POST /baa/sign       { signerName, signerEmail, plan? }   (best-effort,
//        authenticated with the just-issued access token)
// The mutation chains them via queryFn so the component keeps a single submit.
export const onboardingApi = createApi({
  reducerPath: 'onboardingApi',
  baseQuery: baseQueryWithReauth,
  endpoints: (build) => ({
    onboard: build.mutation<LoginResponse, OnboardRequest>({
      async queryFn(payload, _api, _extraOptions, baseQuery) {
        const { account, agency, baa } = payload;

        const registerRes = await baseQuery({
          url: '/auth/register',
          method: 'POST',
          body: {
            email: account.email,
            password: account.password,
            firstName: account.firstName,
            lastName: account.lastName,
            organizationName: agency.agencyName,
          },
        });
        if (registerRes.error) return { error: registerRes.error };

        const auth = (registerRes.data as ApiEnvelope<LoginResponse>).data;

        // Best-effort BAA signature; a failure here shouldn't undo the account.
        // Sign with the freshly returned access token explicitly (the auth
        // slice isn't updated until the caller stores these credentials).
        if (baa?.acknowledged) {
          await baseQuery({
            url: '/baa/sign',
            method: 'POST',
            headers: { Authorization: `Bearer ${auth.accessToken}` },
            body: {
              signerName: `${account.firstName} ${account.lastName}`.trim(),
              signerEmail: account.email,
              plan: agency.tier,
            },
          });
        }

        return { data: auth };
      },
    }),
  }),
});

export const { useOnboardMutation } = onboardingApi;
