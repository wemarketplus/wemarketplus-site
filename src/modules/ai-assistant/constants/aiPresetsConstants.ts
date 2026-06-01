import type { AiPreset } from '../types/aiAssistantTypes';

// Mirrors the preset chips on wemarketplus-site's AI Assistant panel.
export const AI_PRESETS: readonly AiPreset[] = [
  {
    id: 'cold-sources',
    label: 'Find cold sources',
    prompt: 'Which referral sources have we not touched in 14+ days?',
  },
  {
    id: 'draft-followup',
    label: 'Draft follow-up',
    prompt: 'Draft a personalized follow-up to a hospital discharge planner.',
  },
  {
    id: 'convert-pending',
    label: 'Convert pending',
    prompt: 'Suggest the right next step for prospects in Pending Admission.',
  },
  {
    id: 'family-calls',
    label: 'Family calls',
    prompt: 'Outline talking points for an empathetic family call.',
  },
];
