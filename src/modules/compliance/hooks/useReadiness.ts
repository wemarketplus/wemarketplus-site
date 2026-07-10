import type { ReadinessScore } from '../types/complianceTypes';

// No readiness endpoint exists yet. Return a zeroed structure and an isEmpty
// flag so the page renders an empty/coming-soon state instead of fixture data.
// Swap for a GET /compliance/readiness query when it ships.
const EMPTY_READINESS: ReadinessScore = {
  score: 0,
  rating: '—',
  status: 'needs-remediation',
  controls: [],
};

export function useReadiness() {
  return { readiness: EMPTY_READINESS, isEmpty: true };
}
