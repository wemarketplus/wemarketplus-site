// Public surface of the onboarding module. Internals stay private.
export { OnboardingPage } from './pages/OnboardingPage';
export { default as onboardingReducer } from './store/onboardingSlice';
export { onboardingApi } from './api/onboardingApi';
export type {
  OnboardingStep,
  AccountInfo,
  AgencyInfo,
  BAASignature,
  OnboardRequest,
} from './types/onboardingTypes';
