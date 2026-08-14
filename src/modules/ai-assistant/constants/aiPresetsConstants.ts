import type { AiPreset } from '../types/aiAssistantTypes';

export const AI_STUB_DELAY_MS = 600;

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

/**
 * Copilot's starting questions for a CommunityLink FIELD technician.
 *
 * A separate list because AI_PRESETS above is a sales list — cold referral
 * sources, follow-up drafts, pending admissions. None of it is answerable by, or
 * useful to, someone whose screen is a queue of work orders, and offering it would
 * make Copilot look like a tool that was not built for them. The field guide's own
 * framing sets the scope: "an AI helper you can ask maintenance-related questions."
 */
export const AI_FIELD_PRESETS: readonly AiPreset[] = [
  {
    id: 'triage-order',
    label: 'What first?',
    prompt:
      'I have several open work orders at different priorities. How should I decide which to do first?',
  },
  {
    id: 'make-ready-checklist',
    label: 'Make-ready checklist',
    prompt:
      'What should I check before marking an apartment make-ready complete for a new move-in?',
  },
  {
    id: 'diagnose-issue',
    label: 'Diagnose an issue',
    prompt:
      'A resident reports their room is not heating. What should I check, in order?',
  },
  {
    id: 'write-resolution',
    label: 'Write the resolution',
    prompt:
      'Help me write a clear resolution note for a repair I just finished, so the next person knows what was done.',
  },
];
