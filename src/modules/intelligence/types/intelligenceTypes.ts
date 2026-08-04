// Mirrors wemarketplus-backend/src/intelligence/dto/intelligence-response.dto.ts.
// There is no generated client, so this file IS the contract — keep it in step with
// that DTO or the screens silently render undefined.

export interface IntelligenceWindow {
  from: string;
  to: string;
}

export interface RevenueBySource {
  referralSourceId: string;
  name: string;
  priorityTier: string | null;
  invoiced: number;
  paid: number;
  outstanding: number;
  contractValue: number;
  admits: number;
  invoiceCount: number;
}

export interface RevenueByMonth {
  month: string;
  invoiced: number;
  paid: number;
}

export interface RevenueIntelligence {
  window: IntelligenceWindow;
  totalInvoiced: number;
  totalPaid: number;
  totalOutstanding: number;
  /**
   * Revenue that carries a referral source. The gap to `totalInvoiced` is shown in
   * the UI rather than hidden: reporting only the attributable slice as if it were
   * the whole is exactly what made the previous (data-less) screens misleading.
   */
  attributedInvoiced: number;
  unattributedInvoiced: number;
  bySource: RevenueBySource[];
  byMonth: RevenueByMonth[];
}

export interface MarketingRoiBySource {
  referralSourceId: string;
  name: string;
  notes: number;
  visits: number;
  jobsCompleted: number;
  touches: number;
  prospects: number;
  admits: number;
  lost: number;
  conversionRate: number | null;
  revenue: number;
  revenuePerTouch: number | null;
  touchesPerAdmit: number | null;
}

export interface MarketingRoi {
  window: IntelligenceWindow;
  /** True = revenue per unit of logged effort, not per currency spent. */
  effortBased: boolean;
  totalTouches: number;
  totalRevenue: number;
  bySource: MarketingRoiBySource[];
}

export interface LeaderboardRow {
  userId: string;
  name: string;
  email: string;
  role: string;
  admits: number;
  revenue: number;
  touches: number;
  jobsCompleted: number;
  appointmentsCompleted: number;
  goalTarget: number | null;
  goalAchieved: number | null;
  goalPace: number | null;
  rank: number;
}

export interface Leaderboard {
  window: IntelligenceWindow;
  rows: LeaderboardRow[];
}

export interface ReferralFunnelRow {
  referralSourceId: string;
  name: string;
  status: string | null;
  priorityTier: string | null;
  leads: number;
  prospects: number;
  admits: number;
  lost: number;
  open: number;
  revenue: number;
  score: number | null;
}

export interface IntakeByOrigin {
  sourceType: string;
  leads: number;
  converted: number;
  disqualified: number;
  conversionRate: number | null;
}

export interface ReferralAnalytics {
  window: IntelligenceWindow;
  funnel: ReferralFunnelRow[];
  intakeByOrigin: IntakeByOrigin[];
  lostReasons: { lostReason: string; count: number }[];
}

/** Query window shared by all four endpoints. */
export interface IntelligenceQuery {
  from?: string;
  to?: string;
}

export interface IntelligenceKpi {
  id: string;
  label: string;
  value: string;
  delta?: string;
  /** Shown under the value when a figure needs an honesty caveat. */
  note?: string;
}

export interface IntelligenceUiState {
  range: '7d' | '30d' | 'mtd' | '90d';
}

export interface RangeOption {
  value: IntelligenceUiState['range'];
  label: string;
}
