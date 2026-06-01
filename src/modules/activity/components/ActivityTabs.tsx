import { Calendar, ScrollText, Pin, Goal } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import { setActivityTab } from '../store/activitySlice';
import type { ActivityUiState } from '../types/activityTypes';

const TABS: ReadonlyArray<{
  value: ActivityUiState['activeTab'];
  label: string;
  icon: typeof Calendar;
}> = [
  { value: 'calendar', label: 'Calendar', icon: Calendar },
  { value: 'notes', label: 'Notes', icon: ScrollText },
  { value: 'reminders', label: 'Reminders', icon: Pin },
  { value: 'goals', label: 'Daily goals', icon: Goal },
];

export function ActivityTabs() {
  const dispatch = useAppDispatch();
  const active = useAppSelector((s) => s.activity.activeTab);

  return (
    <nav className="flex flex-wrap gap-1.5">
      {TABS.map((t) => {
        const Icon = t.icon;
        const selected = active === t.value;
        return (
          <button
            key={t.value}
            type="button"
            onClick={() => dispatch(setActivityTab(t.value))}
            className={cn(
              'inline-flex items-center gap-2 rounded-pill border px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              selected
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
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
