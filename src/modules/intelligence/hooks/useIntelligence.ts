import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import {
  useGetLeaderboardQuery,
  useGetMarketingRoiQuery,
  useGetReferralAnalyticsQuery,
  useGetRevenueIntelligenceQuery,
} from '../api/intelligenceApi';
import { rangeToWindow } from '../constants/intelligenceConstants';
import type { IntelligenceKpi } from '../types/intelligenceTypes';
import {
  attributionRate,
  formatMoney,
  formatRate,
} from '../utils/intelligenceUtils';

/**
 * The Intelligence screens' single data source. Previously this hook returned empty
 * arrays with `isEmpty: true` because no backend endpoint existed; it now reads the
 * four real endpoints over the window the user picked.
 *
 * Every KPI below is a figure the API actually returned or a ratio of two of them —
 * nothing is estimated, and nothing is carried over from a fixture. Where a figure
 * cannot be computed the formatter emits an em dash rather than a zero.
 */
export function useIntelligence() {
  const range = useAppSelector((s) => s.intelligence.range);
  const window = useMemo(() => rangeToWindow(range), [range]);

  const revenueQuery = useGetRevenueIntelligenceQuery(window);
  const roiQuery = useGetMarketingRoiQuery(window);
  const leaderboardQuery = useGetLeaderboardQuery(window);
  const analyticsQuery = useGetReferralAnalyticsQuery(window);

  const revenue = revenueQuery.data;
  const roi = roiQuery.data;

  const kpis: IntelligenceKpi[] = useMemo(() => {
    if (!revenue) return [];
    const attributed = attributionRate(
      revenue.attributedInvoiced,
      revenue.totalInvoiced,
    );
    return [
      {
        id: 'attributed-revenue',
        label: 'Attributed revenue',
        value: formatMoney(revenue.attributedInvoiced),
        // The unattributed remainder is surfaced, not hidden. A high number here
        // means invoices are being raised without linking them to the account that
        // produced them — a data-entry problem the screen should expose.
        note:
          revenue.unattributedInvoiced > 0
            ? `${formatMoney(revenue.unattributedInvoiced)} not yet attributed`
            : undefined,
      },
      {
        id: 'collected',
        label: 'Collected',
        value: formatMoney(revenue.totalPaid),
        note:
          revenue.totalOutstanding > 0
            ? `${formatMoney(revenue.totalOutstanding)} outstanding`
            : undefined,
      },
      {
        id: 'attribution-rate',
        label: 'Attribution coverage',
        value: formatRate(attributed),
        note: 'Share of billed revenue traceable to a referral source',
      },
      {
        id: 'revenue-per-touch',
        label: 'Revenue per touch',
        value:
          roi && roi.totalTouches > 0
            ? formatMoney(roi.totalRevenue / roi.totalTouches)
            : '—',
        note: 'Logged effort, not marketing spend',
      },
    ];
  }, [revenue, roi]);

  const isLoading =
    revenueQuery.isLoading ||
    roiQuery.isLoading ||
    leaderboardQuery.isLoading ||
    analyticsQuery.isLoading;

  const error =
    revenueQuery.error ??
    roiQuery.error ??
    leaderboardQuery.error ??
    analyticsQuery.error;

  return {
    range,
    window,
    kpis,
    revenue,
    roi,
    leaderboard: leaderboardQuery.data?.rows ?? [],
    analytics: analyticsQuery.data,
    isLoading,
    error,
    /**
     * True only when the API answered and there is genuinely nothing to show — as
     * distinct from still loading, which must not render an empty state.
     */
    isEmpty:
      !isLoading &&
      !error &&
      (revenue?.totalInvoiced ?? 0) === 0 &&
      (leaderboardQuery.data?.rows.length ?? 0) === 0,
    refetch: () => {
      void revenueQuery.refetch();
      void roiQuery.refetch();
      void leaderboardQuery.refetch();
      void analyticsQuery.refetch();
    },
  };
}
