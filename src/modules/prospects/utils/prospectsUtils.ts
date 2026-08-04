import { ProspectStatus as ProspectStatusEnum } from '@/shared/types';
import type { Prospect, ProspectStatus, Urgency } from '@/shared/types';
import { ProspectStage, type ProspectRecord } from '../types/prospectsTypes';

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

export function mapProspectRecord(r: ProspectRecord): Prospect {
  return {
    id: r.id,
    name: r.pipelineName ?? r.patientName,
    status: stageToStatus(r.stage),
    phone: r.phone ?? '',
    email: '',
    referralSource: r.referralSourceId ?? '',
    assignedMarketer: r.assignedTo ?? '',
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
