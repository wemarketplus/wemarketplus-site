// Single yes/no cell in the feature comparison matrix (see ComparisonTable).
export function ComparisonCell({ on }: { on: boolean }) {
  return on ? (
    <span className="font-bold text-sage">Yes</span>
  ) : (
    <span className="text-white/[0.15]">—</span>
  );
}
