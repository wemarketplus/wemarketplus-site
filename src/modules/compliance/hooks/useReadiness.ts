import { READINESS_FIXTURE } from '../constants/portalContent';

// Readiness score is fixture-backed (the source runs in demo mode with this
// exact payload). Swap for a GET /compliance/readiness query when it ships.
export function useReadiness() {
  return { readiness: READINESS_FIXTURE, isUsingFixture: true };
}
