import { ProspectStatus } from '@/shared/types';
import type { PipelineColumnConfig } from '../types/pipelineTypes';

// Kanban column order — mirrors the site's pipeline view.
export const PIPELINE_COLUMNS: ReadonlyArray<PipelineColumnConfig> = [
  {
    status: ProspectStatus.Inquiry,
    label: 'Inquiry',
    tone: 'border-azure/30 bg-azure/10 text-azure',
  },
  {
    status: ProspectStatus.PendingAdmission,
    label: 'Pending admission',
    tone: 'border-warning/30 bg-warning/10 text-warning',
  },
  {
    status: ProspectStatus.Admitted,
    label: 'Admitted',
    tone: 'border-success/30 bg-success/10 text-success',
  },
  {
    status: ProspectStatus.Lost,
    label: 'Lost',
    tone: 'border-white/[0.08] bg-white/[0.03] text-muted',
  },
];
