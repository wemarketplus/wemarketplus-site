import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import {
  ONBOARDING_DRAFT_KEY,
  ONBOARDING_DRAFT_TTL_MS,
} from '../constants/onboardingConstants';
import type {
  AccountInfo,
  AgencyInfo,
  BAASignature,
  OnboardingDraft,
  OnboardingState,
  OnboardingStep,
} from '../types/onboardingTypes';

const EMPTY_DRAFT: OnboardingDraft = { account: {}, agency: {}, baa: {} };

// Restore a draft from localStorage if it's still within the 2h window. We
// deliberately stash this in localStorage (not redux-persist) because it's a
// short-lived, single-flow value — no need to pull it into the persisted root.
const loadDraft = (): { draft: OnboardingDraft; expiresAt: number | null } => {
  if (typeof window === 'undefined') {
    return { draft: EMPTY_DRAFT, expiresAt: null };
  }
  try {
    const raw = window.localStorage.getItem(ONBOARDING_DRAFT_KEY);
    if (!raw) return { draft: EMPTY_DRAFT, expiresAt: null };
    const parsed = JSON.parse(raw) as { draft: OnboardingDraft; expiresAt: number };
    if (!parsed.expiresAt || parsed.expiresAt < Date.now()) {
      window.localStorage.removeItem(ONBOARDING_DRAFT_KEY);
      return { draft: EMPTY_DRAFT, expiresAt: null };
    }
    return { draft: parsed.draft, expiresAt: parsed.expiresAt };
  } catch {
    return { draft: EMPTY_DRAFT, expiresAt: null };
  }
};

const persistDraft = (draft: OnboardingDraft, expiresAt: number): void => {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(
      ONBOARDING_DRAFT_KEY,
      JSON.stringify({ draft, expiresAt }),
    );
  } catch {
    // localStorage may be full or disabled — silently ignore; UI keeps state
    // in memory either way.
  }
};

const clearDraft = (): void => {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(ONBOARDING_DRAFT_KEY);
  } catch {
    // no-op
  }
};

const { draft, expiresAt } = loadDraft();

const initialState: OnboardingState = {
  currentStep: 'account',
  draft,
  draftExpiresAt: expiresAt,
  completed: false,
};

const onboardingSlice = createSlice({
  name: 'onboarding',
  initialState,
  reducers: {
    goToStep(state, action: PayloadAction<OnboardingStep>) {
      state.currentStep = action.payload;
    },
    saveAccount(state, action: PayloadAction<AccountInfo>) {
      state.draft.account = action.payload;
      const expires = Date.now() + ONBOARDING_DRAFT_TTL_MS;
      state.draftExpiresAt = expires;
      persistDraft(state.draft, expires);
    },
    saveAgency(state, action: PayloadAction<AgencyInfo>) {
      state.draft.agency = action.payload;
      const expires = Date.now() + ONBOARDING_DRAFT_TTL_MS;
      state.draftExpiresAt = expires;
      persistDraft(state.draft, expires);
    },
    saveBAA(state, action: PayloadAction<BAASignature>) {
      state.draft.baa = action.payload;
      const expires = Date.now() + ONBOARDING_DRAFT_TTL_MS;
      state.draftExpiresAt = expires;
      persistDraft(state.draft, expires);
    },
    markCompleted(state) {
      state.completed = true;
      state.draft = EMPTY_DRAFT;
      state.draftExpiresAt = null;
      clearDraft();
    },
    resetOnboarding() {
      clearDraft();
      return {
        currentStep: 'account',
        draft: EMPTY_DRAFT,
        draftExpiresAt: null,
        completed: false,
      };
    },
  },
});

export const {
  goToStep,
  saveAccount,
  saveAgency,
  saveBAA,
  markCompleted,
  resetOnboarding,
} = onboardingSlice.actions;
export default onboardingSlice.reducer;
