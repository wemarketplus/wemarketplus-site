import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { AuthenticatedUser } from '@/modules/auth/types/authTypes';

// SuperAdmin tenant impersonation — wemarketplus-backend/src/impersonation.
//   POST /impersonation/start { tenantId } -> token pair for the tenant owner,
//     access token carries an `impersonatedBy` claim (audited server-side).
//   POST /impersonation/stop -> { stopped: true } (audit only; the client
//     discards the impersonation token and restores the operator's session).
export interface StartImpersonationResponse {
  accessToken: string;
  refreshToken?: string;
  user: AuthenticatedUser;
  impersonating: true;
  tenantId: string;
  organizationName: string;
}

export const impersonationApi = createApi({
  reducerPath: 'impersonationApi',
  baseQuery: baseQueryWithReauth,
  endpoints: (build) => ({
    startImpersonation: build.mutation<StartImpersonationResponse, string>({
      query: (tenantId) => ({
        url: '/impersonation/start',
        method: 'POST',
        body: { tenantId },
      }),
      transformResponse: (res: ApiEnvelope<StartImpersonationResponse>) => res.data,
    }),
    stopImpersonation: build.mutation<{ stopped: true }, void>({
      query: () => ({ url: '/impersonation/stop', method: 'POST' }),
      transformResponse: (res: ApiEnvelope<{ stopped: true }>) => res.data,
    }),
  }),
});

export const { useStartImpersonationMutation, useStopImpersonationMutation } =
  impersonationApi;
