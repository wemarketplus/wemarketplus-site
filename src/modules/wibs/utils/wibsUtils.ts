import { opt, optNum } from '@/shared/ui/entity';
import type { WibStatus } from '../constants/wibsConstants';
import type { CreateWibRequest, UpdateWibRequest, WibRecord } from '../types/wibsTypes';
import type { WibFormValues } from '../schema/wibSchema';

// Form values -> POST /wibs body. wibName + sourceUrl required; the rest are
// optional and stripped when blank (email/website are IsEmail/IsUrl gated).
export function toCreateWib(values: WibFormValues): CreateWibRequest {
  return {
    wibName: values.wibName.trim(),
    sourceUrl: values.sourceUrl.trim(),
    ...opt('shortName', values.shortName),
    ...opt('state', values.state),
    ...(values.status ? { status: values.status as WibStatus } : {}),
    ...opt('wibPhone', values.wibPhone),
    ...opt('wibEmail', values.wibEmail),
    ...opt('website', values.website),
    ...optNum('maxAwardPerEin', values.maxAwardPerEin),
    ...optNum('matchRequirementPct', values.matchRequirementPct),
    ...opt('wibType', values.wibType),
    ...opt('nextSteps', values.nextSteps),
    ...opt('blockers', values.blockers),
    ...opt('notes', values.notes),
  };
}

// PATCH body is the same whitelisted shape (partial merge on the backend). The
// update DTO accepts sourceUrl too, so no field needs dropping here.
export function toUpdateWib(values: WibFormValues): UpdateWibRequest {
  return toCreateWib(values);
}

// Seeds the edit form from an existing record (nulls -> '' / undefined).
export function toWibFormValues(record: WibRecord): WibFormValues {
  return {
    wibName: record.wibName,
    sourceUrl: record.sourceUrl ?? '',
    shortName: record.shortName ?? '',
    state: record.state ?? '',
    status: record.status,
    wibPhone: record.wibPhone ?? '',
    wibEmail: record.wibEmail ?? '',
    website: record.website ?? '',
    maxAwardPerEin: record.maxAwardPerEin ?? undefined,
    matchRequirementPct: record.matchRequirementPct ?? undefined,
    wibType: record.wibType ?? '',
    nextSteps: record.nextSteps ?? '',
    blockers: record.blockers ?? '',
    notes: record.notes ?? '',
  };
}
