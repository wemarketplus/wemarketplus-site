import type { OwnerPipelineDeal } from '../types/ownerPortalTypes';

export function dealsForStage(
  deals: readonly OwnerPipelineDeal[],
  stage: OwnerPipelineDeal['stage'],
): readonly OwnerPipelineDeal[] {
  return deals.filter((d) => d.stage === stage);
}

export function sumEstimatedMrr(deals: readonly OwnerPipelineDeal[]): number {
  return deals.reduce((n, d) => n + d.estimatedMrr, 0);
}
