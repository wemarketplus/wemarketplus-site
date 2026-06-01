import { METRICS } from '../../constants/landingContent';
import { cn } from '@/shared/utils/cn';

const TONE: Record<string, string> = {
  sage: 'text-sage',
  azure: 'text-azure',
  amber: 'text-amber',
  purple: 'text-[#c9aeff]',
};

// index.html metrics strip — 5 big stats.
export function MetricsStrip() {
  return (
    <section className="border-b border-white/[0.06]">
      <div className="mx-auto grid max-w-7xl grid-cols-2 gap-6 px-6 py-10 sm:grid-cols-3 lg:grid-cols-5">
        {METRICS.map((m) => (
          <div key={m.label} className="text-center">
            <div className={cn('font-serif-display text-4xl font-black leading-none', TONE[m.tone])}>
              {m.value}
            </div>
            <div className="mt-1.5 text-[11px] uppercase tracking-[0.12em] text-muted">
              {m.label}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
