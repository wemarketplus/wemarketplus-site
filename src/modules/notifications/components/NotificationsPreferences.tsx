import { Switch } from '@/shared/ui';
import { NOTIFICATION_TYPE_LABELS } from '../constants/notificationsConstants';
import { useNotificationPreferences } from '../hooks/useNotificationPreferences';

function labelFor(type: string): { label: string; description: string } {
  return NOTIFICATION_TYPE_LABELS[type] ?? { label: type, description: '' };
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
    <div className="divide-y divide-border/[0.09]">
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
            <Switch
              checked={item.inApp}
              disabled={isSaving}
              onCheckedChange={(next) => void toggle(item, next)}
              aria-label={`In-app notifications for ${meta.label}`}
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
