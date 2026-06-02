import { STEP_ORDER } from '../constants/onboardingConstants';
import type { OnboardingStep } from '../types/onboardingTypes';

// Pure cross-step derivations shared by the wizard hook and progress UI.

export function getStepIndex(step: OnboardingStep): number {
  return STEP_ORDER.indexOf(step);
}

export function getStepProgress(step: OnboardingStep): number {
  return ((getStepIndex(step) + 1) / STEP_ORDER.length) * 100;
}
