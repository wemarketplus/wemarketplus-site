import { useAppDispatch } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import {
  SETTINGS_TAB_ICONS,
  SETTINGS_TAB_LABELS,
} from '../constants/settingsConstants';
import { useSettingsTabs } from '../hooks/useSettingsTabs';
import { setActiveTab } from '../store/settingsSlice';

export function SettingsTabs() {
  const dispatch = useAppDispatch();
  // Product/role-filtered, and `active` is the RESOLVED tab — so the strip can
  // never render with nothing selected. See the hook.
  const { tabs, activeTab: active } = useSettingsTabs();

  return (
    <nav className="flex flex-wrap gap-1.5" aria-label="Settings sections">
      {tabs.map((tab) => {
        const Icon = SETTINGS_TAB_ICONS[tab];
        const selected = active === tab;
        return (
          <button
            key={tab}
            type="button"
            onClick={() => dispatch(setActiveTab(tab))}
            aria-pressed={selected}
            className={cn(
              'inline-flex items-center gap-2 rounded-pill border px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
              selected
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {SETTINGS_TAB_LABELS[tab]}
          </button>
        );
      })}
    </nav>
  );
}
