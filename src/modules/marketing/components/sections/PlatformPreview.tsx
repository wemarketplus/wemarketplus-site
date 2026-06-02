import { Pill } from '@/shared/ui/data-display';
import { SectionHeading } from '../SectionHeading';
import { cn } from '@/shared/utils/cn';
import {
  PREVIEW_FEED,
  PREVIEW_KPIS,
  PREVIEW_PIPELINE,
  PREVIEW_PIPELINE_BADGE,
  PREVIEW_SIDE_NAV,
} from '../../constants/platformPreviewContent';

// index.html #preview "Live Platform Preview" — a #070b14 browser-chrome
// window (KPIs + prospect pipeline + cold alert) beside a Live Activity feed,
// matching the .crm-window / .activity-feed mockup tokens.
// .crm-kpi tile tints per KPI tone (matches index.html inline tile styles).
const KPI_TILE: Record<string, string> = {
  'text-[#f87171]': 'border-[#ef4444]/[0.15] bg-[#ef4444]/[0.08]',
  'text-amber': 'border-amber/[0.15] bg-amber/[0.08]',
  'text-azure': 'border-azure/[0.22] bg-azure/10',
  'text-sage': 'border-sage/[0.22] bg-sage/10',
};

export function PlatformPreview() {
  return (
    <section id="preview" className="mx-auto max-w-[1200px] px-7 py-20">
      <SectionHeading
        kicker="Live Platform Preview"
        tone="azure"
        title="See It Before You Buy"
        body="Real hospice workflows — not generic CRM templates. Every screen built for how your team actually works."
      />

      <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-[1fr_300px]">
        {/* .crm-window — #070b14 browser chrome */}
        <div className="overflow-hidden rounded-[16px] border border-white/10 bg-[#070b14] shadow-[0_40px_100px_rgba(0,0,0,0.6)]">
          <div className="flex items-center gap-2.5 border-b border-white/[0.08] bg-[#050910] px-[14px] py-2.5">
            <div className="flex gap-[5px]">
              <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
              <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
            </div>
            <span className="mx-2 flex-1 truncate rounded-[5px] bg-white/[0.04] px-2.5 py-[3px] font-mono text-[10px] text-faint">
              app.wemarketplus.com/dashboard
            </span>
            <span className="inline-flex items-center gap-[5px] text-[10px] font-bold text-sage">
              <span className="h-[5px] w-[5px] animate-breathe rounded-full bg-sage" />{' '}
              Live
            </span>
          </div>
          <div className="flex">
            <aside className="hidden w-[150px] shrink-0 border-r border-white/[0.08] bg-[#050910] px-2 py-2.5 sm:block">
              {PREVIEW_SIDE_NAV.map((s) => (
                <div key={s.group}>
                  <p className="px-1.5 pb-1 pt-2 text-[9px] font-bold uppercase tracking-[0.1em] text-faint">
                    {s.group}
                  </p>
                  {s.items.map((it) => (
                    <div
                      key={it}
                      className={
                        it === 'Dashboard'
                          ? 'mb-px rounded-[5px] bg-azure/[0.14] px-2.5 py-1.5 text-[11px] font-semibold text-azure'
                          : 'mb-px rounded-[5px] px-2.5 py-1.5 text-[11px] font-semibold text-muted'
                      }
                    >
                      {it}
                    </div>
                  ))}
                </div>
              ))}
            </aside>
            <div className="min-w-0 flex-1 p-4">
              <div className="mb-3.5 grid grid-cols-4 gap-2">
                {PREVIEW_KPIS.map((k) => (
                  <div
                    key={k.label}
                    className={cn(
                      'rounded-[6px] border px-2.5 py-[9px]',
                      KPI_TILE[k.tone] ?? 'border-white/[0.06] bg-white/[0.02]',
                    )}
                  >
                    <p className="mb-[3px] text-[8px] font-bold uppercase tracking-[0.07em] text-faint">
                      {k.label}
                    </p>
                    <p className={`text-[19px] font-extrabold leading-none ${k.tone}`}>
                      {k.value}
                    </p>
                  </div>
                ))}
              </div>
              <p className="mb-2 text-[9px] font-bold uppercase tracking-[0.07em] text-faint">
                Prospect Pipeline
              </p>
              <div>
                {PREVIEW_PIPELINE.map((p) => (
                  <div
                    key={p.name}
                    className="flex items-center justify-between border-b border-white/[0.04] py-[9px] text-[12px] last:border-b-0"
                  >
                    <span className="font-semibold text-foreground">{p.name}</span>
                    <span className="flex items-center gap-3">
                      <Pill
                        tone={p.pill}
                        className={cn('inline-flex items-center', PREVIEW_PIPELINE_BADGE[p.pill])}
                      >
                        {p.label}
                      </Pill>
                      <span className="w-16 text-right text-muted">{p.meta}</span>
                    </span>
                  </div>
                ))}
              </div>
              <div className="mt-3 flex items-center justify-between rounded-[6px] border border-[#ef4444]/[0.15] bg-[#ef4444]/[0.05] px-[11px] py-2 text-[11px]">
                <span className="font-semibold text-[#fbbf24]">
                  Cold Alert — Physician Office (22 days)
                </span>
                <span className="rounded-pill bg-amber px-2.5 py-[3px] text-[10px] font-bold text-[#06080e]">
                  Log Touch
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* .activity-feed — translucent surface-1 panel */}
        <div className="overflow-hidden rounded-[16px] border border-white/[0.08] bg-white/[0.03]">
          <div className="flex items-center justify-between border-b border-white/[0.08] px-4 py-3">
            <span className="text-[13px] font-bold text-foreground">Live Activity</span>
            <span className="inline-flex items-center gap-[5px] text-[11px] font-bold text-sage">
              <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-sage" />{' '}
              Live
            </span>
          </div>
          <ul>
            {PREVIEW_FEED.map((f, i) => (
              <li
                key={i}
                className="flex items-start gap-2.5 border-b border-white/[0.035] px-4 py-[11px] last:border-b-0"
              >
                <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${f.dot}`} />
                <div className="min-w-0 flex-1">
                  <p className="text-[12px] font-semibold leading-[1.35] text-foreground">
                    {f.title}
                  </p>
                  <p className="mt-0.5 text-[11px] text-faint">{f.detail}</p>
                </div>
                <span className="shrink-0 pt-0.5 text-[10px] text-faint">{f.when}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
