import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import { CONCESSION_STATUS, LEAKAGE_STATUS, type ConcessionStatus, type LeakageStatus } from './clFinancialApiConstants';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
import type { ClFinancialUiState } from '../types/clFinancialTypes';
import type {
  RevenueFormValues,
  ConcessionFormValues,
  CompetitorFormValues,
  LeakageFormValues,
  LocFormValues,
} from '../schema/clFinancialSchema';

export const CL_FINANCIAL_PAGE_SIZE = 20;

export const FINANCIAL_VIEWS: ReadonlyArray<{
  value: ClFinancialUiState['view'];
  label: string;
}> = [
  { value: 'ledger', label: 'Ledger' },
  { value: 'leakage', label: 'Leakage' },
  { value: 'concessions', label: 'Concessions' },
  { value: 'competitors', label: 'Competitors' },
  { value: 'loc', label: 'LOC calculator' },
];

export const CONCESSION_STATUS_LABELS: Record<ConcessionStatus, string> = {
  [CONCESSION_STATUS.Pending]: 'Pending',
  [CONCESSION_STATUS.Approved]: 'Approved',
  [CONCESSION_STATUS.Rejected]: 'Rejected',
};

export const CONCESSION_STATUS_PILL: Record<ConcessionStatus, PillProps['tone']> = {
  [CONCESSION_STATUS.Pending]: 'y',
  [CONCESSION_STATUS.Approved]: 'g',
  [CONCESSION_STATUS.Rejected]: 'r',
};

export const CONCESSION_STATUS_OPTIONS: readonly EntitySelectOption[] = Object.entries(
  CONCESSION_STATUS_LABELS,
).map(([value, label]) => ({ value, label }));

export const LEAKAGE_STATUS_LABELS: Record<LeakageStatus, string> = {
  [LEAKAGE_STATUS.Active]: 'Active',
  [LEAKAGE_STATUS.Ongoing]: 'Ongoing',
  [LEAKAGE_STATUS.Review]: 'Review',
  [LEAKAGE_STATUS.FixNeeded]: 'Fix needed',
  [LEAKAGE_STATUS.Resolved]: 'Resolved',
};

export const LEAKAGE_STATUS_PILL: Record<LeakageStatus, PillProps['tone']> = {
  [LEAKAGE_STATUS.Active]: 'r',
  [LEAKAGE_STATUS.Ongoing]: 'y',
  [LEAKAGE_STATUS.Review]: 'b',
  [LEAKAGE_STATUS.FixNeeded]: 'r',
  [LEAKAGE_STATUS.Resolved]: 'g',
};

export const LEAKAGE_STATUS_OPTIONS: readonly EntitySelectOption[] = Object.entries(
  LEAKAGE_STATUS_LABELS,
).map(([value, label]) => ({ value, label }));

// Common leakage issue types (free-form varchar on the backend).
export const LEAKAGE_TYPE_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'underpriced_unit', label: 'Underpriced unit' },
  { value: 'concession', label: 'Concession overrun' },
  { value: 'unbilled_fee', label: 'Unbilled fee' },
  { value: 'unauthorized_waiver', label: 'Unauthorized waiver' },
  { value: 'extended_vacancy', label: 'Extended vacancy' },
  { value: 'other', label: 'Other' },
];

// Revenue category buckets (free-form varchar on the backend).
export const REVENUE_CATEGORY_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'rent', label: 'Rent' },
  { value: 'care_fees', label: 'Care fees' },
  { value: 'community_fee', label: 'Community fee' },
  { value: 'ancillary', label: 'Ancillary' },
  { value: 'other', label: 'Other' },
];

// --- form field descriptors ---------------------------------------------

export const REVENUE_FIELDS: ReadonlyArray<EntityField<RevenueFormValues>> = [
  /**
   * `min` greys out past days in the picker — the shared mechanism, passed as
   * the FUNCTION so "today" is read fresh each render rather than frozen at
   * module load. First of three layers; RevenueFormModal re-checks a typed value
   * on submit and CreateClRevenueEntryDto enforces it server-side.
   */
  { name: 'entryDate', label: 'Entry date', type: 'date', min: todayLocalDate },
  { name: 'category', label: 'Category', type: 'select', options: REVENUE_CATEGORY_OPTIONS },
  { name: 'amount', label: 'Amount', type: 'text', placeholder: '10800' },
  { name: 'budgetAmount', label: 'Budgeted', type: 'text', placeholder: '11000' },
  { name: 'description', label: 'Description', type: 'textarea', full: true, placeholder: 'Occupied units rent roll…' },
];

export const CONCESSION_FIELDS: ReadonlyArray<EntityField<ConcessionFormValues>> = [
  { name: 'type', label: 'Concession type', full: true, placeholder: 'First month free' },
  { name: 'valueAmount', label: 'Value', type: 'text', placeholder: '2000' },
  { name: 'status', label: 'Status', type: 'select', options: CONCESSION_STATUS_OPTIONS },
  { name: 'reason', label: 'Reason', type: 'textarea', full: true, placeholder: 'Competitive match, long-term lead…' },
];

export const COMPETITOR_FIELDS: ReadonlyArray<EntityField<CompetitorFormValues>> = [
  { name: 'name', label: 'Community name', full: true, placeholder: 'Sunrise of Dallas' },
  { name: 'city', label: 'City', placeholder: 'Dallas' },
  { name: 'distanceMiles', label: 'Distance (mi)', type: 'text', placeholder: '3.5' },
  { name: 'rateIl', label: 'IL rate', type: 'text', placeholder: '3800' },
  { name: 'rateAl', label: 'AL rate', type: 'text', placeholder: '4800' },
  { name: 'rateMc', label: 'MC rate', type: 'text', placeholder: '6200' },
  { name: 'occupancyPct', label: 'Occupancy %', type: 'text', placeholder: '92' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'Positioning, incentives…' },
];

export const LOC_FIELDS: ReadonlyArray<EntityField<LocFormValues>> = [
  { name: 'level', label: 'Level', type: 'text', placeholder: '1' },
  { name: 'label', label: 'Label', placeholder: 'Level 2 — Moderate assist' },
  { name: 'addOnRate', label: 'Add-on rate', type: 'text', placeholder: '500' },
  { name: 'description', label: 'Description', type: 'textarea', full: true, placeholder: 'What this level covers…' },
];

export const LEAKAGE_FIELDS: ReadonlyArray<EntityField<LeakageFormValues>> = [
  { name: 'issue', label: 'Issue', full: true, placeholder: 'Unit 106 leased below market rate' },
  { name: 'type', label: 'Type', type: 'select', options: LEAKAGE_TYPE_OPTIONS },
  { name: 'monthlyImpact', label: 'Monthly impact', type: 'text', placeholder: '380' },
  { name: 'status', label: 'Status', type: 'select', options: LEAKAGE_STATUS_OPTIONS },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'Root cause, remediation plan…' },
];
