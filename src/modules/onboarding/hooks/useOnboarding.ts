import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import {
  goToStep,
  markCompleted,
  resetOnboarding,
  saveAccount,
  saveAgency,
  saveBAA,
} from '../store/onboardingSlice';
import { STEP_ORDER } from '../constants/onboardingConstants';
import type { OnboardingStep } from '../types/onboardingTypes';

export function useOnboarding() {
  const dispatch = useAppDispatch();
  const state = useAppSelector((s) => s.onboarding);

  const currentIndex = STEP_ORDER.indexOf(state.currentStep);

  const advanceTo = useCallback(
    (step: OnboardingStep) => dispatch(goToStep(step)),
    [dispatch],
  );

  const next = useCallback(() => {
    const nextStep = STEP_ORDER[currentIndex + 1];
    if (nextStep) dispatch(goToStep(nextStep));
  }, [currentIndex, dispatch]);

  const back = useCallback(() => {
    const prevStep = STEP_ORDER[currentIndex - 1];
    if (prevStep) dispatch(goToStep(prevStep));
  }, [currentIndex, dispatch]);

  return {
    ...state,
    stepIndex: currentIndex,
    stepCount: STEP_ORDER.length,
    progress: ((currentIndex + 1) / STEP_ORDER.length) * 100,
    advanceTo,
    next,
    back,
    saveAccount: (v: Parameters<typeof saveAccount>[0]) => dispatch(saveAccount(v)),
    saveAgency: (v: Parameters<typeof saveAgency>[0]) => dispatch(saveAgency(v)),
    saveBAA: (v: Parameters<typeof saveBAA>[0]) => dispatch(saveBAA(v)),
    markCompleted: () => dispatch(markCompleted()),
    reset: () => dispatch(resetOnboarding()),
  };
}
