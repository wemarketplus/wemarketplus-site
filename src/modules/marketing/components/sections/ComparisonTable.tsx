import { HOSPICE_COMPARISON } from '../../constants/comparisonContent';

const Cell = ({ on }: { on: boolean }) =>
  on ? (
    <span className="font-bold text-sage">Yes</span>
  ) : (
    <span className="text-muted-soft">—</span>
  );

// index.html "Full Feature Comparison" — Pro / Max / Gold matrix.
export function ComparisonTable() {
  return (
    <section className="mx-auto max-w-3xl px-6 py-20">
      <h2 className="mb-8 text-center font-serif-display text-3xl text-foreground sm:text-4xl">
        Full Feature Comparison
      </h2>
      <div className="overflow-hidden rounded-[14px] border border-white/[0.09] bg-surface">
        <table className="w-full text-[13px]">
          <thead className="bg-white/[0.02] text-[10px] uppercase tracking-[0.1em]">
            <tr>
              <th className="px-4 py-3 text-left text-muted-soft">Feature</th>
              <th className="px-4 py-3 text-left text-azure">Pro</th>
              <th className="px-4 py-3 text-left text-sage">Max</th>
              <th className="px-4 py-3 text-left text-gold">Gold</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.05]">
            {HOSPICE_COMPARISON.map((r) => (
              <tr key={r.feature}>
                <td className="px-4 py-3 font-semibold text-foreground">{r.feature}</td>
                <td className="px-4 py-3"><Cell on={r.pro} /></td>
                <td className="px-4 py-3"><Cell on={r.max} /></td>
                <td className="px-4 py-3"><Cell on={r.gold} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
