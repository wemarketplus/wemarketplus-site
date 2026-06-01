import { Bot, Database, Phone, Sparkles, Upload, Webhook } from 'lucide-react';
import type { IntegrationTile } from '../types/integrationsTypes';

export const INTEGRATIONS_CATALOG: readonly IntegrationTile[] = [
  {
    id: 'ai-assistant',
    name: 'AI assistant',
    description: 'Drafts, summaries, and prospect scoring.',
    icon: Sparkles,
    status: 'connected',
    category: 'workflow',
  },
  {
    id: 'aircall',
    name: 'Aircall',
    description: 'Phone, SMS, and email inside the CRM.',
    icon: Phone,
    status: 'available',
    category: 'communications',
  },
  {
    id: 'data-import',
    name: 'CSV / Excel import',
    description: 'Bulk-load prospects and referral sources.',
    icon: Upload,
    status: 'available',
    category: 'data',
  },
  {
    id: 'playbooks',
    name: 'Playbook generator',
    description: 'AI-generated scripts and visit templates (Max tier).',
    icon: Bot,
    status: 'beta',
    category: 'workflow',
  },
  {
    id: 'snowflake',
    name: 'Warehouse export',
    description: 'Stream warehouse-ready events to Snowflake/BigQuery.',
    icon: Database,
    status: 'available',
    category: 'analytics',
  },
  {
    id: 'webhooks',
    name: 'Webhooks',
    description: 'Forward CRM events to your own systems.',
    icon: Webhook,
    status: 'available',
    category: 'data',
  },
];
