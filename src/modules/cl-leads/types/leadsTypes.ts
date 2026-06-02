import type { Lead, LeadStatus } from '@/shared/types';

export type { Lead };

// Local in-memory store for the demo: the lead list is editable (Add Lead
// modal, inline status change) but not persisted — mirrors the HTML demo,
// which keeps everything in page state and resets on reload.
export interface LeadsUiState {
  statusFilter: LeadStatus | 'all';
  // Leads added during this session, prepended to the fixture list.
  added: Lead[];
  // Status overrides keyed by lead id (covers fixture + added leads).
  statusOverrides: Record<string, LeadStatus>;
  addModalOpen: boolean;
}

// Add Lead form payload — mirrors the 15-field modal in
// communitylinkmax-demo.html.
export interface NewLeadInput {
  name: string;
  careType: Lead['careType'];
  status: LeadStatus;
  urgency: Lead['urgency'];
  source: string;
  followUpDate: string;
  phone: string;
  email: string;
  notes?: string;
}

// --- Component prop types ---

export interface LeadsTableProps {
  leads: readonly Lead[];
}
