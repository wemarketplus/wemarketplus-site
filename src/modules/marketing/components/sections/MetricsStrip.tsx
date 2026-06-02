import { METRICS } from '../../constants/landingContent';
import { cn } from '@/shared/utils/cn';

const TONE: Record<string, string> = {
  sage: 'text-sage',
  azure: 'text-azure',
  amber: 'text-amber',
  purple: 'text-[#a78bfa]',
};

// index.html .metrics strip — 5 big stats in Outfit bold (NOT serif), a
// 1000px 5-column grid with vertical dividers, top/bottom rules and a faint
// surface tint.
export function MetricsStrip() {
  return (
    <section className="border-y border-white/[0.08] bg-white/[0.03]">
      <div className="mx-auto grid max-w-[1000px] grid-cols-5">
        {METRICS.map((m, i) => (
          <div
            key={m.label}
            className={cn(
              'px-3 py-7 text-center',
              i !== METRICS.length - 1 && 'border-r border-white/[0.08]',
            )}
          >
            <div
              className={cn(
                'text-[clamp(22px,2.8vw,36px)] font-extrabold leading-none tracking-[-0.03em]',
                TONE[m.tone],
              )}
            >
              {m.value}
            </div>
            <div className="mt-[5px] text-[11px] font-semibold uppercase tracking-[0.06em] text-faint">
              {m.label}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
