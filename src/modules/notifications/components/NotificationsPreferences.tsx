import { cn } from '@/shared/utils/cn';
import { NOTIFICATION_TYPE_LABELS } from '../constants/notificationsConstants';
import { useNotificationPreferences } from '../hooks/useNotificationPreferences';
import type { NotificationPreferenceItem } from '../types/notificationsTypes';

function labelFor(type: string): { label: string; description: string } {
  return NOTIFICATION_TYPE_LABELS[type] ?? { label: type, description: '' };
}

// In-app on/off toggle for a single notification type. A plain accessible
// button (no dedicated Switch component exists in the design system yet).
function InAppToggle({
  item,
  disabled,
  onToggle,
}: {
  item: NotificationPreferenceItem;
  disabled: boolean;
  onToggle: (next: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={item.inApp}
      disabled={disabled}
      onClick={() => onToggle(!item.inApp)}
      className={cn(
        'relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors disabled:opacity-50',
        item.inApp
          ? 'border-primary/40 bg-primary/70'
          : 'border-white/[0.12] bg-white/[0.06]',
      )}
    >
      <span
        className={cn(
          'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
          item.inApp ? 'translate-x-6' : 'translate-x-1',
        )}
      />
    </button>
  );
}

export function NotificationsPreferences() {
  const { items, isLoading, isError, isSaving, toggle } = useNotificationPreferences();

  if (isLoading) {
    return <p className="px-4 py-6 text-sm text-muted">Loading preferences...</p>;
  }
  if (isError) {
    return (
      <p className="px-4 py-6 text-sm text-warning">
        Could not load your notification preferences.
      </p>
    );
  }

  return (
    <div className="divide-y divide-white/[0.06]">
      {items.map((item) => {
        const meta = labelFor(item.type);
        return (
          <div
            key={item.type}
            className="flex items-center justify-between gap-4 px-4 py-4"
          >
            <div>
              <p className="text-sm font-medium text-foreground">{meta.label}</p>
              {meta.description && (
                <p className="text-xs text-muted">{meta.description}</p>
              )}
            </div>
            <InAppToggle
              item={item}
              disabled={isSaving}
              onToggle={(next) => void toggle(item, next)}
            />
          </div>
        );
      })}
      {items.length === 0 && (
        <p className="px-4 py-6 text-sm text-muted">
          No configurable notification types.
        </p>
      )}
    </div>
  );
}
