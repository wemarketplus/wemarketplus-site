import { displayName, type NameTable } from '@/shared/hooks';
import { ProspectStatus as ProspectStatusEnum } from '@/shared/types';
import type { Prospect, ProspectStatus, Urgency } from '@/shared/types';
import { ProspectStage, type ProspectRecord } from '../types/prospectsTypes';
import type { CreateProspectRequest, UpdateProspectRequest } from '../types/prospectsTypes';
import type { NewProspectFormValues } from '../schema/prospectSchema';

// The backend ProspectResponseDto (patientName/stage/aiAdmitScore/...) maps
// onto the UI's Prospect view-model (name/status/conversionRisk/...). Shared
// by the prospects list and the pipeline board so both render the same shape.
function stageToStatus(stage: ProspectStage): ProspectStatus {
  switch (stage) {
    case ProspectStage.Admitted:
      return ProspectStatusEnum.Admitted;
    case ProspectStage.Lost:
    case ProspectStage.Inactive:
      return ProspectStatusEnum.Lost;
    // Mid-funnel stages (both pipeline types) read as "pending admission" in the
    // coarse 4-value list view; the Kanban board uses the real stage instead.
    case ProspectStage.Pending:
    case ProspectStage.Evaluation:
    case ProspectStage.Contacted:
    case ProspectStage.Eligibility:
    case ProspectStage.FaceToFace:
    case ProspectStage.ConsentOrder:
    case ProspectStage.FirstVisit:
    case ProspectStage.InService:
    case ProspectStage.Active:
    case ProspectStage.Champion:
      return ProspectStatusEnum.PendingAdmission;
    case ProspectStage.Inquiry:
    case ProspectStage.NewReferral:
    case ProspectStage.Identified:
    default:
      return ProspectStatusEnum.Inquiry;
  }
}

/**
 * Display names for the ids a prospect row carries. A ProspectRecord only stores
 * `referralSourceId` / `assignedTo` — bare uuid columns, and the entity declares
 * no TypeORM relation, so the API cannot join a name in. The caller resolves them
 * from the referral-source and user lists.
 *
 * Resolved with `displayName`, which yields '' for an id it cannot place rather
 * than falling back to the id: these two fields used to be assigned the uuid
 * itself, which is what put a raw "053d0a2b-…" in the Source column.
 */
export interface ProspectNameLookups {
  referralSources?: NameTable;
  users?: NameTable;
}

export function mapProspectRecord(
  r: ProspectRecord,
  names: ProspectNameLookups = {},
): Prospect {
  return {
    id: r.id,
    name: r.pipelineName ?? r.patientName,
    status: stageToStatus(r.stage),
    phone: r.phone ?? '',
    email: '',
    // The FACILITY this referral came from. In HospiceLink a referral source IS
    // the facility/account (see the ReferralSource entity and
    // HOSPICELINK-USER-GUIDE §6.1), so this one field answers both names: the
    // linked account's name when the fan-out resolved one, and the free text the
    // user typed when it did not. Same precedence the drawer's Facility row uses
    // — without the fallback an unlinked row rendered an empty cell even though
    // the user HAD typed a facility.
    referralSource:
      displayName(names.referralSources, r.referralSourceId) ||
      (r.facilityName ?? ''),
    assignedMarketer: displayName(names.users, r.assignedTo),
    nextStep: '',
    // Real pipeline timing now exists: prefer the stage-entry stamp over updatedAt.
    followUpDate: r.stageEnteredAt ?? r.updatedAt,
    urgency: r.urgency as Urgency,
    // Carried through explicitly so the Triage column can render it. `conversionRisk`
    // below reuses the same number for the legacy risk display; keeping both means the
    // table does not have to know which of the two names a caller populated.
    aiAdmitScore: r.aiAdmitScore,
    conversionRisk: r.aiAdmitScore ?? undefined,
    notes: r.notes ?? undefined,
    lastContactDate: r.updatedAt,
  };
}

// Add/edit form <-> POST/PATCH /prospects body. Blank optionals are dropped so
// the backend's whitelist DTO never sees an empty string on an optional field.
export function toCreateProspect(values: NewProspectFormValues): CreateProspectRequest {
  return {
    patientName: values.patientName.trim(),
    stage: values.stage,
    urgency: values.urgency,
    ...(values.facilityName?.trim() ? { facilityName: values.facilityName.trim() } : {}),
    ...(values.referringPhysician?.trim()
      ? { referringPhysician: values.referringPhysician.trim() }
      : {}),
    ...(values.diagnosis?.trim() ? { diagnosis: values.diagnosis.trim() } : {}),
    ...(values.phone?.trim() ? { phone: values.phone.trim() } : {}),
    ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
  };
}

export function toUpdateProspect(values: NewProspectFormValues): UpdateProspectRequest {
  return toCreateProspect(values);
}

// Seeds the edit form from an existing record.
export function toProspectFormValues(record: ProspectRecord): NewProspectFormValues {
  return {
    patientName: record.patientName,
    facilityName: record.facilityName ?? '',
    stage: record.stage,
    urgency: record.urgency,
    referringPhysician: record.referringPhysician ?? '',
    diagnosis: record.diagnosis ?? '',
    phone: record.phone ?? '',
    notes: record.notes ?? '',
  };
}

interface FilterArgs {
  search: string;
  status: ProspectStatus | 'all';
  urgency: Urgency | 'all';
}

export function filterProspects(
  prospects: readonly Prospect[],
  { search, status, urgency }: FilterArgs,
): readonly Prospect[] {
  const needle = search.trim().toLowerCase();
  return prospects.filter((p) => {
    if (status !== 'all' && p.status !== status) return false;
    if (urgency !== 'all' && p.urgency !== urgency) return false;
    if (!needle) return true;
    return (
      p.name.toLowerCase().includes(needle) ||
      p.email.toLowerCase().includes(needle) ||
      p.referralSource.toLowerCase().includes(needle)
    );
  });
}
