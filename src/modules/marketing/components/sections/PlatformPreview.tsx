import { Pill } from '@/shared/ui/data-display';

// index.html "Live Platform Preview" — a browser-chrome window showing the
// dashboard (KPIs + prospect pipeline + cold alert) beside a Live Activity
// feed. Static reproduction of the marketing mockup.

const KPIS = [
  { label: 'Overdue', value: '2', tone: 'text-[#f87171]' },
  { label: 'Due Today', value: '3', tone: 'text-amber' },
  { label: 'Re-Engage', value: '3', tone: 'text-azure' },
  { label: 'Admitted', value: '3', tone: 'text-sage' },
] as const;

const PIPELINE = [
  { name: 'Mary J.', pill: 'r' as const, label: 'Hot', meta: 'Due Today' },
  { name: 'John T.', pill: 'y' as const, label: 'Warm', meta: 'Due May 8' },
  { name: 'Dorothy F.', pill: 'g' as const, label: 'Admitted', meta: 'Active' },
  { name: 'Helen P.', pill: 'b' as const, label: 'Cold Alert', meta: '18 days' },
];

const SIDE_NAV = [
  { group: 'MAIN', items: ['Dashboard'] },
  { group: 'MARKETING', items: ['Add Referral', 'Prospect Records', 'Pipeline', 'Territory View'] },
  { group: 'ACTIVITY', items: ['Notes', 'AI Assistant'] },
  { group: 'TOOLS', items: ['CSV Import', 'Referral Portal'] },
];

const FEED = [
  { title: 'Reminder marked complete', detail: 'Follow-up closed', when: 'Just now', dot: 'bg-amber' },
  { title: 'New prospect added', detail: 'Assigned to team', when: 'Just now', dot: 'bg-sage' },
  { title: 'Touch logged — SNF visit', detail: 'In-Person contact', when: 'Just now', dot: 'bg-azure' },
  { title: 'Touch logged — SNF visit', detail: 'In-Person contact', when: 'Just now', dot: 'bg-azure' },
  { title: 'New prospect added', detail: 'Assigned to team', when: 'Just now', dot: 'bg-sage' },
  { title: 'Mary J. moved to Pending Admission', detail: 'Baylor Territory', when: '2m ago', dot: 'bg-sage' },
];

export function PlatformPreview() {
  return (
    <section id="preview" className="mx-auto max-w-7xl px-6 py-20">
      <div className="mb-10 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-azure">
          Live Platform Preview
        </p>
        <h2 className="mt-3 font-serif-display text-3xl text-foreground sm:text-4xl">
          See It Before You Buy
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-sm text-muted">
          Real hospice workflows — not generic CRM templates. Every screen built for
          how your team actually works.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_300px]">
        {/* Browser-chrome CRM window */}
        <div className="overflow-hidden rounded-[14px] border border-white/[0.09] bg-surface">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-2.5">
            <span className="h-3 w-3 rounded-full bg-[#ff5f57]" />
            <span className="h-3 w-3 rounded-full bg-[#febc2e]" />
            <span className="h-3 w-3 rounded-full bg-[#28c840]" />
            <span className="ml-3 flex-1 truncate rounded-md bg-surface-raised px-3 py-1 text-[11px] text-muted-soft">
              app.wemarketplus.com/dashboard
            </span>
            <span className="inline-flex items-center gap-1.5 text-[11px] text-sage">
              <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-sage" /> Live
            </span>
          </div>
          <div className="flex">
            <aside className="hidden w-[150px] shrink-0 space-y-3 border-r border-white/[0.06] p-3 sm:block">
              {SIDE_NAV.map((s) => (
                <div key={s.group}>
                  <p className="px-1 pb-1 text-[8px] font-black uppercase tracking-[0.12em] text-[#334d6e]">
                    {s.group}
                  </p>
                  {s.items.map((it) => (
                    <div
                      key={it}
                      className={
                        it === 'Dashboard'
                          ? 'rounded-[6px] bg-azure px-2 py-1 text-[11px] font-bold text-[#081426]'
                          : 'px-2 py-1 text-[11px] text-[#d0d8e8]'
                      }
                    >
                      {it}
                    </div>
                  ))}
                </div>
              ))}
            </aside>
            <div className="min-w-0 flex-1 space-y-3 p-4">
              <div className="grid grid-cols-4 gap-2">
                {KPIS.map((k) => (
                  <div key={k.label} className="rounded-[10px] border border-white/[0.06] bg-white/[0.02] px-3 py-2.5">
                    <p className="text-[9px] uppercase tracking-[0.1em] text-muted-soft">{k.label}</p>
                    <p className={`mt-1 text-2xl font-black leading-none ${k.tone}`}>{k.value}</p>
                  </div>
                ))}
              </div>
              <p className="pt-1 text-[10px] font-black uppercase tracking-[0.1em] text-muted-soft">
                Prospect Pipeline
              </p>
              <div className="divide-y divide-white/[0.05]">
                {PIPELINE.map((p) => (
                  <div key={p.name} className="flex items-center justify-between py-2 text-[12px]">
                    <span className="font-semibold text-foreground">{p.name}</span>
                    <span className="flex items-center gap-3">
                      <Pill tone={p.pill}>{p.label}</Pill>
                      <span className="w-16 text-right text-muted-soft">{p.meta}</span>
                    </span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between rounded-[10px] border border-amber/30 bg-amber/[0.08] px-3 py-2.5 text-[12px]">
                <span className="text-amber">Cold Alert — Physician Office (22 days)</span>
                <span className="rounded-pill bg-amber px-2.5 py-1 text-[11px] font-bold text-[#081426]">
                  Log Touch
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Live Activity feed */}
        <div className="rounded-[14px] border border-white/[0.09] bg-surface">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
            <span className="text-sm font-bold text-foreground">Live Activity</span>
            <span className="inline-flex items-center gap-1.5 text-[11px] text-sage">
              <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-sage" /> Live
            </span>
          </div>
          <ul className="divide-y divide-white/[0.05]">
            {FEED.map((f, i) => (
              <li key={i} className="flex items-start gap-2.5 px-4 py-3">
                <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${f.dot}`} />
                <div className="min-w-0 flex-1">
                  <p className="text-[12px] font-semibold text-foreground">{f.title}</p>
                  <p className="text-[11px] text-muted">{f.detail}</p>
                </div>
                <span className="shrink-0 text-[10px] text-muted-soft">{f.when}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
