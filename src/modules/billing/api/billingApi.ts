import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import { BILLING_TAGS } from '../constants/billingConstants';
import type {
  BillingPortalResponse,
  SubscriptionRecord,
} from '../types/billingTypes';

// TODO(backend): ship GET /subscription-status and POST /billing/portal-session.
// The site's subscription-status.html already shapes its UI around the same
// payload — when the backend lands, this slice will work without UI changes.
export const billingApi = createApi({
  reducerPath: 'billingApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [BILLING_TAGS.Subscription],
  endpoints: (build) => ({
    getSubscription: build.query<SubscriptionRecord, void>({
      query: () => ({ url: '/subscription-status' }),
      transformResponse: (res: ApiEnvelope<SubscriptionRecord>) => res.data,
      providesTags: [BILLING_TAGS.Subscription],
    }),
    openPortalSession: build.mutation<BillingPortalResponse, void>({
      query: () => ({ url: '/billing/portal-session', method: 'POST' }),
      transformResponse: (res: ApiEnvelope<BillingPortalResponse>) => res.data,
    }),
  }),
});

export const { useGetSubscriptionQuery, useOpenPortalSessionMutation } = billingApi;
