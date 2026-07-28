import { useMemo, useState } from 'react';
import { ALL_ROLES, ROLE_LABELS } from '@/shared/rbac';
import { Button, Card, CardContent, Select } from '@/shared/ui/core';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { ALERT_CHANNEL_OPTIONS, ALERT_TYPES } from '../constants/adminSettingsConstants';
import { useListAlertSettingsQuery, useUpsertAlertSettingMutation } from '../api/adminSettingsApi';
import { AlertChannel } from '../types/adminSettingsApiTypes';

// Alert Settings (Admin-only, Max tier): per-alert-type enable toggle, role
// targeting, and delivery channel. Each row saves independently.
export function AlertSettingsPage() {
  const { data, isLoading, error } = useListAlertSettingsQuery();
  const [upsert, { isLoading: isSaving, error: saveError }] = useUpsertAlertSettingMutation();
  const [savedKey, setSavedKey] = useState<string | null>(null);

  const byType = useMemo(() => {
    const map = new Map(data?.map((s) => [s.alertType, s]) ?? []);
    return ALERT_TYPES.map((def) => ({
      def,
      enabled: map.get(def.key)?.enabled ?? true,
      channel: map.get(def.key)?.channel ?? AlertChannel.Email,
      roles: map.get(def.key)?.recipientRoles ?? [],
    }));
  }, [data]);

  const [draft, setDraft] = useState<Record<string, { enabled: boolean; channel: AlertChannel; roles: string[] }>>({});

  const rowState = (key: string) => draft[key] ?? byType.find((r) => r.def.key === key)!;

  const update = (key: string, patch: Partial<{ enabled: boolean; channel: AlertChannel; roles: string[] }>) =>
    setDraft((d) => ({ ...d, [key]: { ...rowState(key), ...patch } }));

  const toggleRole = (key: string, role: string) => {
    const current = rowState(key).roles;
    const roles = current.includes(role) ? current.filter((r) => r !== role) : [...current, role];
    update(key, { roles });
  };

  const save = async (key: string) => {
    const row = rowState(key);
    await upsert({ alertType: key, enabled: row.enabled, channel: row.channel, recipientRoles: row.roles }).unwrap();
    setSavedKey(key);
    setTimeout(() => setSavedKey((k) => (k === key ? null : k)), 2000);
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Alert settings</h1>
        <p className="text-sm text-muted">Who gets notified, and how, for each event.</p>
      </header>

      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
          Failed to load alert settings.
        </p>
      )}
      {saveError && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
          {extractApiErrorMessage(saveError, 'Failed to save alert setting')}
        </p>
      )}

      {isLoading ? (
        <div className="rounded-[12px] border border-white/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
          Loading…
        </div>
      ) : (
        <div className="space-y-3">
          {byType.map(({ def }) => {
            const row = rowState(def.key);
            return (
              <Card key={def.key}>
                <CardContent className="space-y-3 pt-6">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h2 className="text-sm font-bold text-foreground">{def.label}</h2>
                      <p className="text-xs text-muted">{def.description}</p>
                    </div>
                    <label className="flex shrink-0 cursor-pointer items-center gap-2 text-xs text-muted">
                      <input
                        type="checkbox"
                        checked={row.enabled}
                        onChange={(e) => update(def.key, { enabled: e.target.checked })}
                        className="h-4 w-4 accent-primary"
                      />
                      Enabled
                    </label>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    {ALL_ROLES.map((role) => (
                      <label key={role} className="flex cursor-pointer items-center gap-1.5 text-xs text-muted">
                        <input
                          type="checkbox"
                          checked={row.roles.includes(role)}
                          onChange={() => toggleRole(def.key, role)}
                          className="accent-primary"
                        />
                        {ROLE_LABELS[role]}
                      </label>
                    ))}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted">Channel:</span>
                    <Select
                      value={row.channel}
                      onChange={(e) => update(def.key, { channel: e.target.value as AlertChannel })}
                      className="w-40"
                    >
                      {ALERT_CHANNEL_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </Select>
                    <Button size="sm" onClick={() => save(def.key)} disabled={isSaving}>
                      {savedKey === def.key ? 'Saved' : 'Save'}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
