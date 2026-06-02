import { HOSPICE_COMPARISON } from '../../constants/comparisonContent';
import { ComparisonCell } from './ComparisonCell';

// index.html "Full Feature Comparison" — Pro / Max / Gold matrix.
export function ComparisonTable() {
  return (
    <section className="mx-auto max-w-[1100px] px-7 pb-12 pt-14">
      <h3 className="mb-5 text-center font-serif-display text-[24px] tracking-[-0.02em] text-foreground">
        Full Feature Comparison
      </h3>
      <div className="overflow-x-auto rounded-[16px] border border-white/[0.08] bg-white/[0.03]">
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr className="bg-white/[0.02]">
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-left text-[11px] font-bold uppercase tracking-[0.07em] text-faint">
                Feature
              </th>
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-center text-[11px] font-bold uppercase tracking-[0.07em] text-azure">
                Pro
              </th>
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-center text-[11px] font-bold uppercase tracking-[0.07em] text-sage">
                Max
              </th>
              <th className="border-b border-white/[0.08] px-[18px] py-[13px] text-center text-[11px] font-bold uppercase tracking-[0.07em] text-amber">
                Gold
              </th>
            </tr>
          </thead>
          <tbody>
            {HOSPICE_COMPARISON.map((r, i) => {
              const last = i === HOSPICE_COMPARISON.length - 1;
              const border = last ? '' : 'border-b border-white/[0.04]';
              return (
                <tr key={r.feature}>
                  <td className={`px-[18px] py-[10px] text-left font-semibold text-foreground ${border}`}>
                    {r.feature}
                  </td>
                  <td className={`px-[18px] py-[10px] text-center ${border}`}>
                    <ComparisonCell on={r.pro} />
                  </td>
                  <td className={`px-[18px] py-[10px] text-center ${border}`}>
                    <ComparisonCell on={r.max} />
                  </td>
                  <td className={`px-[18px] py-[10px] text-center ${border}`}>
                    <ComparisonCell on={r.gold} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
