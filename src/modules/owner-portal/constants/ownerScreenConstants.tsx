import { Mail, MessageSquare, Phone, Sliders, ToggleRight, UserCog } from 'lucide-react';
import type { PillProps } from '@/shared/ui/data-display';
import type {
  OwnerAdminControl,
  OwnerChurnRow,
  OwnerCommunication,
  OwnerCustomer,
  OwnerInsight,
  OwnerPipelineDeal,
} from '../types/ownerPortalTypes';

// Presentational lookup maps + page-level config, lifted out of the owner
// screen files so the pages stay thin.

export const STATUS_PILL: Record<OwnerCustomer['status'], PillProps['tone']> = {
  active: 'g',
  past_due: 'y',
  churned: 'r',
};

export const STAGES: Array<{
  value: OwnerPipelineDeal['stage'];
  label: string;
  tone: string;
}> = [
  { value: 'demo', label: 'Demo', tone: 'text-azure' },
  { value: 'pilot', label: 'Pilot', tone: 'text-primary' },
  { value: 'contract', label: 'Contract', tone: 'text-warning' },
  { value: 'won', label: 'Won', tone: 'text-success' },
  { value: 'lost', label: 'Lost', tone: 'text-destructive' },
];

export const RECOVERY_LABEL: Record<OwnerChurnRow['recoveryAttempt'], string> = {
  none: 'Not contacted',
  email_sent: 'Email sent',
  call_scheduled: 'Call scheduled',
  recovered: 'Recovered',
};

export const RECOVERY_TONE: Record<OwnerChurnRow['recoveryAttempt'], string> = {
  none: 'border-destructive/30 bg-destructive/10 text-destructive',
  email_sent: 'border-warning/30 bg-warning/10 text-warning',
  call_scheduled: 'border-azure/30 bg-azure/10 text-azure',
  recovered: 'border-success/30 bg-success/10 text-success',
};

export const SEVERITY_TONE: Record<OwnerInsight['severity'], string> = {
  info: 'border-azure/30 bg-azure/10 text-azure',
  opportunity: 'border-primary/30 bg-primary/10 text-primary',
  risk: 'border-destructive/30 bg-destructive/10 text-destructive',
};

export const CHANNEL_ICON: Record<
  OwnerCommunication['channel'],
  typeof Mail
> = {
  email: Mail,
  call: Phone,
  in_app: MessageSquare,
};

export const OWNER_ADMIN_CONTROLS: readonly OwnerAdminControl[] = [
  {
    id: 'impersonate',
    icon: UserCog,
    title: 'Impersonate user',
    description: 'Sign in as any customer to reproduce an issue from their side.',
    cta: 'Open impersonator',
  },
  {
    id: 'flags',
    icon: ToggleRight,
    title: 'Feature flags',
    description: 'Toggle experimental features per tenant or globally.',
    cta: 'Manage flags',
  },
  {
    id: 'system',
    icon: Sliders,
    title: 'System parameters',
    description: 'Rate limits, queue depths, and AI budget controls.',
    cta: 'Open parameters',
  },
];
