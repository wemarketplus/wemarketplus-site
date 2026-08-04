import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  IntelligenceQuery,
  Leaderboard,
  MarketingRoi,
  ReferralAnalytics,
  RevenueIntelligence,
  WeeklyReport,
} from '../types/intelligenceTypes';

// Verified against wemarketplus-backend/src/intelligence/intelligence.controller.ts:
//   GET /intelligence/revenue?from&to
//   GET /intelligence/roi?from&to
//   GET /intelligence/leaderboard?from&to
//   GET /intelligence/referral-analytics?from&to
//
// This file used to be `// TODO(backend): /intelligence/{...}` + `export {}` — the
// three Intelligence screens rendered with no data source at all. The endpoints now
// exist, and every figure they return is attributable through
// invoices.referralSourceId / invoices.prospectId.
//
// ALL FOUR ARE GOLD-GATED AND MANAGEMENT-ONLY on the server (@RequireProduct
// HospiceLink + @RequireFeature intelligence_* + @Roles admin/owner/manager). A
// tenant below Gold gets 402 UPGRADE_REQUIRED, which baseQueryWithReauth already
// redirects to /billing — so components do not special-case the tier.
const env = <T>(res: ApiEnvelope<T>) => res.data;

export const intelligenceApi = createApi({
  reducerPath: 'intelligenceApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Revenue', 'Roi', 'Leaderboard', 'ReferralAnalytics'],
  endpoints: (build) => ({
    getRevenueIntelligence: build.query<
      RevenueIntelligence,
      IntelligenceQuery | void
    >({
      query: (params) => ({
        url: '/intelligence/revenue',
        params: params ?? undefined,
      }),
      transformResponse: env<RevenueIntelligence>,
      providesTags: ['Revenue'],
    }),

    getMarketingRoi: build.query<MarketingRoi, IntelligenceQuery | void>({
      query: (params) => ({
        url: '/intelligence/roi',
        params: params ?? undefined,
      }),
      transformResponse: env<MarketingRoi>,
      providesTags: ['Roi'],
    }),

    getLeaderboard: build.query<Leaderboard, IntelligenceQuery | void>({
      query: (params) => ({
        url: '/intelligence/leaderboard',
        params: params ?? undefined,
      }),
      transformResponse: env<Leaderboard>,
      providesTags: ['Leaderboard'],
    }),

    getWeeklyReport: build.query<WeeklyReport, void>({
      query: () => ({ url: '/intelligence/weekly-report' }),
      transformResponse: env<WeeklyReport>,
      providesTags: ['Revenue'],
    }),

    getReferralAnalytics: build.query<
      ReferralAnalytics,
      IntelligenceQuery | void
    >({
      query: (params) => ({
        url: '/intelligence/referral-analytics',
        params: params ?? undefined,
      }),
      transformResponse: env<ReferralAnalytics>,
      providesTags: ['ReferralAnalytics'],
    }),
  }),
});

export const {
  useGetRevenueIntelligenceQuery,
  useGetMarketingRoiQuery,
  useGetLeaderboardQuery,
  useGetReferralAnalyticsQuery,
  useGetWeeklyReportQuery,
} = intelligenceApi;
