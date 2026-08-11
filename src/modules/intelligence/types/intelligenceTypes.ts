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

/**
 * Cost-per-admission and the admissions forecast (RevenueOutlookDto).
 *
 * Every money field is nullable because the product has exactly ONE cost input —
 * the monthly marketing spend an admin records in financial settings. Null means
 * "no spend recorded", which the UI must render as unavailable rather than as
 * zero: "we do not know your cost" and "your marketing is free" are different
 * claims and only one is ever true.
 */
export interface RevenueOutlook {
  /** Recorded monthly marketing spend, pro-rated across the window. */
  marketingSpend: number | null;
  /** Mileage reimbursement paid in the window — measured, not entered. */
  mileageCost: number;
  totalCost: number | null;
  admits: number;
  /** Null when cost is unknown OR there were no admissions to divide by. */
  costPerAdmission: number | null;
  /** Blend of run-rate and triage-weighted pipeline. Null if the window is too short. */
  forecastedAdmits: number | null;
  forecastRunRate: number | null;
  forecastPipeline: number | null;
  forecastHorizonDays: number;
  openPipelineCount: number;
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
  outlook: RevenueOutlook;
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

/** Mirrors WeeklyReportDto. The Executive Director's Monday-morning digest. */
export interface WeeklyReport {
  window: IntelligenceWindow;
  leadsReceived: number;
  leadsConverted: number;
  admits: number;
  lost: number;
  revenueBilled: number;
  revenueCollected: number;
  visitsCompleted: number;
  topSources: RevenueBySource[];
  leaderboard: LeaderboardRow[];
  lostReasons: { lostReason: string; count: number }[];
}

/**
 * One rep's row in the marketer-facing standings.
 *
 * Deliberately NARROWER than LeaderboardRow: revenue, email and role are absent
 * because the server never sends them here. The Leaderboard is an admin report
 * carrying per-rep revenue; a marketer sees how they are pacing against the
 * team, not what each colleague bills. See the backend's getMyPerformance.
 */
export interface MyPerformanceRow {
  userId: string;
  name: string;
  rank: number;
  admits: number;
  touches: number;
  jobsCompleted: number;
  appointmentsCompleted: number;
  /**
   * Share of this rep's CLOSED referrals that were admitted, 0–1. Null when
   * nothing has closed yet — "no rate", which a 0 would misreport as a total
   * failure to convert. Open referrals are NOT in the denominator, so a full
   * pipeline never drags the number down.
   */
  conversionRate: number | null;
  /** True for the caller's own row, so it can be highlighted. */
  isMe: boolean;
}

export interface MyPerformance {
  window: IntelligenceWindow;
  /** The caller's own row; null when they have no activity in the window. */
  me: MyPerformanceRow | null;
  standings: MyPerformanceRow[];
}


/** One signed contribution to a scorecard grade, with the reason it applied. */
export interface ScorecardFactor {
  key: string;
  points: number;
  detail: string;
}

/** One account's computed scorecard (ReferralScorecardRowDto). */
export interface ReferralScorecardRow {
  referralSourceId: string;
  name: string;
  priorityTier: string | null;
  status: string | null;
  /** The COMPUTED 1-10 grade. */
  score: number;
  /**
   * The hand-set 1-10 opinion (referral_sources.aiScore). Shown alongside the
   * computed grade so the screen can surface where the team's judgement and the
   * data disagree — which is the most useful thing this report produces.
   */
  handSetScore: number | null;
  factors: ScorecardFactor[];
  referrals: number;
  admits: number;
  revenue: number;
  touches: number;
  lastInteractionAt: string | null;
}

export interface ReferralScorecard {
  window: IntelligenceWindow;
  /** Highest score first. */
  rows: ReferralScorecardRow[];
  computedAt: string;
}
