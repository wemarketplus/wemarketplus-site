import type { IntelligenceUiState, RangeOption } from '../types/intelligenceTypes';

// The hardcoded REVENUE_KPIS / LEADERBOARD fixtures that used to live here are gone.
// They were invented figures ("$184k", "+12.4%", three named marketers) rendered on a
// Gold-tier screen with no data source behind it — the exact "plausible wrong number"
// failure the module-flow document warns about. Every figure now comes from
// /intelligence/*.

export const RANGES: ReadonlyArray<RangeOption> = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'mtd', label: 'Month to date' },
  { value: '90d', label: 'Last 90 days' },
];

/**
 * Turns a UI range into the `from`/`to` window the API takes. Computed on the client
 * so the label the user picked and the window the server aggregates always agree.
 *
 * `mtd` starts at midnight on the 1st of the current month in LOCAL time, not UTC —
 * a marketer in a negative-offset zone checking "month to date" on the 1st must not
 * see an empty screen because UTC is still in last month. Same reasoning as
 * `toDateOnly` on the backend.
 */
export function rangeToWindow(range: IntelligenceUiState['range']): {
  from: string;
  to: string;
} {
  const now = new Date();
  const to = now.toISOString();
  if (range === 'mtd') {
    const start = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
    return { from: start.toISOString(), to };
  }
  const days = range === '7d' ? 7 : range === '30d' ? 30 : 90;
  const start = new Date(now.getTime() - days * 86_400_000);
  return { from: start.toISOString(), to };
}

/** Lead origin slugs -> the labels the intake report shows. */
export const LEAD_ORIGIN_LABELS: Record<string, string> = {
  fax: 'Fax',
  web_form: 'Web form',
  phone: 'Phone',
  email: 'Email',
  spreadsheet_import: 'Spreadsheet import',
  walk_in: 'Walk-in',
};

/** Lost-reason slugs -> labels, for the re-engagement breakdown. */
export const LOST_REASON_LABELS: Record<string, string> = {
  not_eligible: 'Not eligible',
  chose_competitor: 'Chose competitor',
  declined: 'Declined',
  deceased: 'Deceased',
  other: 'Other',
};
