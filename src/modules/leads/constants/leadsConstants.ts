import type { PillProps } from '@/shared/ui/data-display';
import {
  LeadDisqualifyReason,
  LeadSourceType,
  LeadStatus,
} from '../types/leadsTypes';

export const LEADS_TAGS = {
  List: 'Leads.List',
  Detail: 'Leads.Detail',
} as const;

export const LEAD_STATUS_LABELS: Record<LeadStatus, string> = {
  [LeadStatus.New]: 'New',
  [LeadStatus.Reviewing]: 'Reviewing',
  [LeadStatus.Converted]: 'Converted',
  [LeadStatus.Disqualified]: 'Disqualified',
};

export const LEAD_STATUS_PILL: Record<LeadStatus, PillProps['tone']> = {
  [LeadStatus.New]: 'b',
  [LeadStatus.Reviewing]: 'y',
  [LeadStatus.Converted]: 'g',
  [LeadStatus.Disqualified]: 'r',
};

export const LEAD_SOURCE_LABELS: Record<LeadSourceType, string> = {
  [LeadSourceType.Fax]: 'Fax',
  [LeadSourceType.WebForm]: 'Web form',
  [LeadSourceType.Phone]: 'Phone',
  [LeadSourceType.Email]: 'Email',
  [LeadSourceType.SpreadsheetImport]: 'Spreadsheet import',
  [LeadSourceType.WalkIn]: 'Walk-in',
};

export const LEAD_DISQUALIFY_LABELS: Record<LeadDisqualifyReason, string> = {
  [LeadDisqualifyReason.NotEligible]: 'Not eligible',
  [LeadDisqualifyReason.Duplicate]: 'Duplicate',
  [LeadDisqualifyReason.WrongServiceArea]: 'Wrong service area',
  [LeadDisqualifyReason.BadData]: 'Bad data',
};

export const LEAD_STATUS_CHIPS: ReadonlyArray<{
  value: LeadStatus | 'all';
  label: string;
}> = [
  { value: 'all', label: 'All statuses' },
  ...Object.values(LeadStatus).map((value) => ({
    value,
    label: LEAD_STATUS_LABELS[value],
  })),
];

export const LEAD_SOURCE_OPTIONS: ReadonlyArray<{
  value: LeadSourceType;
  label: string;
}> = Object.values(LeadSourceType).map((value) => ({
  value,
  label: LEAD_SOURCE_LABELS[value],
}));

export const LEAD_DISQUALIFY_OPTIONS: ReadonlyArray<{
  value: LeadDisqualifyReason;
  label: string;
}> = Object.values(LeadDisqualifyReason).map((value) => ({
  value,
  label: LEAD_DISQUALIFY_LABELS[value],
}));

/** Statuses that are still actionable (convert / disqualify / edit). */
export const ACTIONABLE_LEAD_STATUSES: ReadonlyArray<LeadStatus> = [
  LeadStatus.New,
  LeadStatus.Reviewing,
];
