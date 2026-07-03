// Public surface of the onboarding-checklist module. The dashboard renders the
// card; completion is derived from existing queries (no new backend endpoints).
export { OnboardingChecklistCard } from './components/OnboardingChecklistCard';
export { useOnboardingChecklist } from './hooks/useOnboardingChecklist';
export type { ChecklistStep } from './hooks/useOnboardingChecklist';
