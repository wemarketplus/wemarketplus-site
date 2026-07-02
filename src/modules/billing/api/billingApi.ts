import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import { BILLING_TAGS } from '../constants/billingConstants';
import type {
  AiUsageToday,
  BillingPortalResponse,
  ConfirmCheckoutRequest,
  CreateCheckoutRequest,
  PlanOption,
  SubscriptionRecord,
} from '../types/billingTypes';

// Verified against wemarketplus-backend/src/billing/billing.controller.ts:
//   GET  /billing/subscription     -> SubscriptionResponseDto
//   GET  /billing/ai-usage/today   -> { count }
//   GET  /billing/plans            -> ResolvedPlan[]  (configured catalog)
//   POST /billing/checkout {planKey?} -> { url }  (Stripe Checkout, subscription mode)
//   POST /billing/checkout/confirm {sessionId} -> SubscriptionResponseDto
//     (verifies the session with Stripe on the success redirect)
//   POST /billing/portal           -> { url }  (Stripe customer portal)
export const billingApi = createApi({
  reducerPath: 'billingApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [BILLING_TAGS.Subscription],
  endpoints: (build) => ({
    getSubscription: build.query<SubscriptionRecord, void>({
      query: () => ({ url: '/billing/subscription' }),
      transformResponse: (res: ApiEnvelope<SubscriptionRecord>) => res.data,
      providesTags: [BILLING_TAGS.Subscription],
    }),
    getAiUsageToday: build.query<AiUsageToday, void>({
      query: () => ({ url: '/billing/ai-usage/today' }),
      transformResponse: (res: ApiEnvelope<AiUsageToday>) => res.data,
    }),
    getPlans: build.query<PlanOption[], void>({
      query: () => ({ url: '/billing/plans' }),
      transformResponse: (res: ApiEnvelope<PlanOption[]>) => res.data,
    }),
    createCheckoutSession: build.mutation<BillingPortalResponse, CreateCheckoutRequest | void>({
      query: (body) => ({ url: '/billing/checkout', method: 'POST', body: body ?? {} }),
      transformResponse: (res: ApiEnvelope<BillingPortalResponse>) => res.data,
    }),
    confirmCheckout: build.mutation<SubscriptionRecord, ConfirmCheckoutRequest>({
      query: (body) => ({ url: '/billing/checkout/confirm', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<SubscriptionRecord>) => res.data,
      invalidatesTags: [BILLING_TAGS.Subscription],
    }),
    openPortalSession: build.mutation<BillingPortalResponse, void>({
      query: () => ({ url: '/billing/portal', method: 'POST' }),
      transformResponse: (res: ApiEnvelope<BillingPortalResponse>) => res.data,
    }),
  }),
});

export const {
  useGetSubscriptionQuery,
  useGetAiUsageTodayQuery,
  useGetPlansQuery,
  useCreateCheckoutSessionMutation,
  useConfirmCheckoutMutation,
  useOpenPortalSessionMutation,
} = billingApi;
