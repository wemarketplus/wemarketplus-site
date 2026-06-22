// Territory priority — mirrors backend TerritoryPriority enum.
export const TERRITORY_PRIORITY = {
  High: 'high',
  Medium: 'medium',
  Low: 'low',
} as const;

export type TerritoryPriority = (typeof TERRITORY_PRIORITY)[keyof typeof TERRITORY_PRIORITY];
