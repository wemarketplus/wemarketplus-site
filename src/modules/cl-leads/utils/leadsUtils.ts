import { opt } from '@/shared/ui/entity';
import {
  CL_LEAD_STAGE,
  type ClCareLevel,
  type ClLeadStage,
  type ClLostReason,
  type ClUrgency,
} from '../constants/clLeadApiConstants';
import type {
  ClLeadRecord,
  CreateClLeadRequest,
  UpdateClLeadRequest,
} from '../types/clLeadApiTypes';
import type { LeadFormValues } from '../schema/leadSchema';

/** Full display name from the record's first/last name parts. */
export function leadName(lead: ClLeadRecord): string {
  return [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() || '—';
}

// Splits a single "Full name" field into firstName / lastName. Everything up to
// the first space is the first name; the remainder (if any) is the last name.
function splitName(fullName: string): { firstName: string; lastName?: string } {
  const trimmed = fullName.trim().replace(/\s+/g, ' ');
  const idx = trimmed.indexOf(' ');
  if (idx === -1) return { firstName: trimmed };
  return { firstName: trimmed.slice(0, idx), lastName: trimmed.slice(idx + 1) };
}

// Form values -> POST /cl/leads body. Drops blank optionals so the DTO's
// IsEmail / Matches(ISO_DATE) rules never see an empty string.
export function toCreateLead(values: LeadFormValues): CreateClLeadRequest {
  const { firstName, lastName } = splitName(values.fullName);
  return {
    firstName,
    ...(lastName ? { lastName } : {}),
    ...opt('phone', values.phone),
    ...opt('email', values.email),
    careLevel: values.careLevel as ClCareLevel,
    stage: values.stage as ClLeadStage,
    urgency: values.urgency as ClUrgency,
    ...opt('source', values.source),
    ...opt('followUpDate', values.followUpDate),
    ...opt('notes', values.notes),
    ...lostReasonPatch(values),
  };
}

/**
 * The loss reason pair, written only when it can be true of the record.
 *
 * Off `lost`, both are sent as explicit NULLS rather than omitted. Omitting means
 * "leave alone", which would let a revived lead keep the reason it was lost for —
 * and while the server clears them itself on a stage change, saying so here keeps
 * the request honest about what the form is asserting rather than relying on a
 * side effect happening somewhere else.
 */
function lostReasonPatch(
  values: LeadFormValues,
): Pick<CreateClLeadRequest, 'lostReason' | 'lostReasonDetail'> {
  if (values.stage !== CL_LEAD_STAGE.Lost) {
    return { lostReason: null, lostReasonDetail: null };
  }
  return {
    lostReason: (values.lostReason || null) as ClLostReason | null,
    // Only `other` carries a note; anything else clears a note left over from a
    // previous answer of `other`.
    lostReasonDetail: values.lostReasonDetail?.trim() || null,
  };
}

// PATCH body is the same partial shape; the backend accepts any subset.
export function toUpdateLead(values: LeadFormValues): UpdateClLeadRequest {
  return toCreateLead(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toLeadFormValues(lead: ClLeadRecord): LeadFormValues {
  return {
    fullName: [lead.firstName, lead.lastName].filter(Boolean).join(' '),
    phone: lead.phone ?? '',
    email: lead.email ?? '',
    careLevel: (lead.careLevel ?? 'IL') as LeadFormValues['careLevel'],
    stage: lead.stage,
    urgency: lead.urgency,
    source: lead.source ?? '',
    followUpDate: lead.followUpDate ?? '',
    notes: lead.notes ?? '',
    lostReason: lead.lostReason ?? '',
    lostReasonDetail: lead.lostReasonDetail ?? '',
  };
}
