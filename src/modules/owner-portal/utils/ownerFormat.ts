// Money + percent + delta formatters for owner-portal screens. Kept module-
// local — these don't need to leak across the rest of the app.

export const formatMoney = (cents: number): string =>
  `$${cents.toLocaleString('en-US', { maximumFractionDigits: 0 })}`;

export const formatCompactMoney = (value: number): string => {
  if (value >= 1_000_000) return `$${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `$${(value / 1_000).toFixed(1)}k`;
  return formatMoney(value);
};

export const formatPercent = (value: number, digits = 1): string =>
  `${(value * 100).toFixed(digits)}%`;
