import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  CreatePortalLinkRequest,
  PortalContext,
  PortalLink,
  PortalLinkQr,
  PortalSubmissionReceipt,
  SubmitPortalReferralRequest,
  UpdatePortalLinkRequest,
} from '../types/referralPortalTypes';

const env = <T>(res: ApiEnvelope<T>) => res.data;

// Verified against wemarketplus-backend/src/referral-portal/referral-portal.controller.ts.
// MANAGEMENT (authenticated, HospiceLink, marketing roles):
//   GET/POST /referral-portal/links · GET /referral-portal/links/:id/qr · PATCH /:id
export const referralPortalApi = createApi({
  reducerPath: 'referralPortalApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['PortalLink'],
  endpoints: (build) => ({
    listPortalLinks: build.query<PortalLink[], { referralSourceId?: string } | void>({
      query: (params) => ({
        url: '/referral-portal/links',
        params: params ?? undefined,
      }),
      transformResponse: env<PortalLink[]>,
      providesTags: ['PortalLink'],
    }),
    getPortalLinkQr: build.query<PortalLinkQr, { id: string; origin: string }>({
      query: ({ id, origin }) => ({
        url: `/referral-portal/links/${id}/qr`,
        params: { origin },
      }),
      transformResponse: env<PortalLinkQr>,
    }),
    createPortalLink: build.mutation<PortalLink, CreatePortalLinkRequest>({
      query: (body) => ({ url: '/referral-portal/links', method: 'POST', body }),
      transformResponse: env<PortalLink>,
      invalidatesTags: ['PortalLink'],
    }),
    updatePortalLink: build.mutation<
      PortalLink,
      { id: string; patch: UpdatePortalLinkRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/referral-portal/links/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<PortalLink>,
      invalidatesTags: ['PortalLink'],
    }),
  }),
});

/**
 * The PUBLIC portal, as a SEPARATE api slice with a plain base query.
 *
 * Deliberately not `baseQueryWithReauth`: that wrapper attaches the logged-in
 * tenant's bearer token and redirects on 401/402. A facility opening this form
 * has no session, and a hospice admin who happens to be logged in must not have
 * their credentials sent to a public endpoint — the token in the URL is the only
 * authorisation this surface should ever carry.
 */
export const publicReferralPortalApi = createApi({
  reducerPath: 'publicReferralPortalApi',
  baseQuery: fetchBaseQuery({ baseUrl: '/api' }),
  endpoints: (build) => ({
    //   GET  /public/referral-portal/:token -> { organizationName, facilityName }
    resolvePortal: build.query<PortalContext, string>({
      query: (token) => ({ url: `/public/referral-portal/${token}` }),
      transformResponse: env<PortalContext>,
    }),
    //   POST /public/referral-portal/:token -> acknowledgement only
    submitPortalReferral: build.mutation<
      PortalSubmissionReceipt,
      { token: string; body: SubmitPortalReferralRequest }
    >({
      query: ({ token, body }) => ({
        url: `/public/referral-portal/${token}`,
        method: 'POST',
        body,
      }),
      transformResponse: env<PortalSubmissionReceipt>,
    }),
  }),
});

export const {
  useListPortalLinksQuery,
  useGetPortalLinkQrQuery,
  useCreatePortalLinkMutation,
  useUpdatePortalLinkMutation,
} = referralPortalApi;

export const { useResolvePortalQuery, useSubmitPortalReferralMutation } =
  publicReferralPortalApi;
