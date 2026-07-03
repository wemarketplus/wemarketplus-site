// Resilient store for the plan a visitor picked on the pricing page, so the
// choice survives the whole signup funnel — including the email verification
// round-trip, where the user often clicks the link in a fresh browser tab that
// has no redux/in-memory state. Backed by localStorage, keyed independently of
// the onboarding draft (which is cleared the moment the account is created).
const PENDING_PLAN_KEY = 'wmp_pending_plan';

// Persist the chosen backend catalog planKey (e.g. "hl_max").
export function setPendingPlan(planKey: string): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(PENDING_PLAN_KEY, planKey);
  } catch {
    // localStorage may be full or disabled — non-fatal; the URL/query param
    // path still carries the plan within a single tab.
  }
}

// Read the pending planKey, or null when none was chosen / storage is empty.
export function getPendingPlan(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    const value = window.localStorage.getItem(PENDING_PLAN_KEY);
    return value && value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

// Clear the pending plan once checkout has started (or the flow is abandoned)
// so a later, plan-less signup doesn't inherit a stale choice.
export function clearPendingPlan(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(PENDING_PLAN_KEY);
  } catch {
    // no-op
  }
}
