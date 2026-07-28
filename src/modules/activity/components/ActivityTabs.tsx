import { cn } from '@/shared/utils/cn';
import { ACTIVITY_TABS } from '../constants/activityConstants';
import { useActivityTabs } from '../hooks/useActivityTabs';

export function ActivityTabs() {
  const { activeTab: active, setTab } = useActivityTabs();

  return (
    <nav className="flex flex-wrap gap-1.5">
      {ACTIVITY_TABS.map((t) => {
        const Icon = t.icon;
        const selected = active === t.value;
        return (
          <button
            key={t.value}
            type="button"
            onClick={() => setTab(t.value)}
            className={cn(
              'inline-flex items-center gap-2 rounded-pill border px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              selected
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        );
      })}
    </nav>
  );
}
