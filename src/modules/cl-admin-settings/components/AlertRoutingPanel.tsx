import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { ALL_ROLES, ROLE_LABELS } from '@/shared/rbac';
import { Button, Card, CardContent, Checkbox, Select } from '@/shared/ui/core';
import { Alert } from '@/shared/ui/data-display';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  ALERT_CHANNEL_OPTIONS,
  alertTypeMeta,
} from '../constants/adminSettingsConstants';
import {
  useListAlertChannelsQuery,
  useListAlertSettingsQuery,
  useUpsertAlertSettingMutation,
} from '../api/adminSettingsApi';
import { AlertChannel } from '../types/adminSettingsApiTypes';

interface RowDraft {
  enabled: boolean;
  channel: AlertChannel;
  roles: string[];
}

/**
 * Alert routing: per alert type, whether it fires, WHO receives it, and over
 * which channel (in-app / email / SMS).
 *
 * Extracted from AlertSettingsPage so the SAME control can appear in two places
 * without being written twice:
 *
 *   - CommunityLink: its own "Alert settings" page (unchanged).
 *   - HospiceLink:   the "Alerts" tab on the Notifications screen, because the
 *                    HospiceLink product guide tells an Office Manager to
 *                    "Click Notifications to control who gets a text or email
 *                    alert, and for what". Following that instruction previously
 *                    landed on a screen with in-app toggles only.
 *
 * PRODUCT-NEUTRAL: the alert TYPES come from GET /alert-settings, which scopes
 * them to the products the tenant holds. A HospiceLink admin sees admissions and
 * lost pipelines; a CommunityLink admin still sees tours and move-ins.
 *
 * Until recently nothing READ these settings — the table had full CRUD, a UI,
 * and zero consumers. AlertDispatchService is now that consumer, which is why an
 * unconfigured row defaults to DISABLED: switching on a dispatcher over
 * long-dormant rows must not start mailing tenants who never asked for it.
 */
export function AlertRoutingPanel() {
  const { data, isLoading, error } = useListAlertSettingsQuery();
  const { data: channels } = useListAlertChannelsQuery();
  const [upsert, { isLoading: isSaving, error: saveError }] =
    useUpsertAlertSettingMutation();
  const [savedKey, setSavedKey] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, RowDraft>>({});

  // Server-supplied rows carry the SAME defaults the dispatcher applies, so what
  // is shown here is what will actually happen.
  const rows = useMemo(
    () =>
      (data ?? []).map((setting) => ({
        key: setting.alertType,
        meta: alertTypeMeta(setting.alertType),
        configured: setting.configured,
        base: {
          enabled: setting.enabled,
          channel: setting.channel,
          roles: setting.recipientRoles ?? [],
        } satisfies RowDraft,
      })),
    [data],
  );

  const unavailable = useMemo(() => {
    const map = new Map<AlertChannel, string>();
    for (const entry of channels ?? []) {
      if (!entry.available) {
        map.set(entry.channel, entry.reason ?? 'Not available.');
      }
    }
    return map;
  }, [channels]);

  const rowState = (key: string): RowDraft => {
    const row = rows.find((r) => r.key === key);
    return (
      draft[key] ??
      row?.base ?? { enabled: false, channel: AlertChannel.Email, roles: [] }
    );
  };

  const update = (key: string, patch: Partial<RowDraft>) =>
    setDraft((d) => ({ ...d, [key]: { ...rowState(key), ...patch } }));

  const toggleRole = (key: string, role: string) => {
    const current = rowState(key).roles;
    update(key, {
      roles: current.includes(role)
        ? current.filter((r) => r !== role)
        : [...current, role],
    });
  };

  const save = async (key: string) => {
    const row = rowState(key);
    await upsert({
      alertType: key,
      enabled: row.enabled,
      channel: row.channel,
      recipientRoles: row.roles,
    }).unwrap();
    setSavedKey(key);
    setTimeout(() => setSavedKey((k) => (k === key ? null : k)), 2000);
  };

  const smsReason = unavailable.get(AlertChannel.Sms);

  return (
    <div className="space-y-4">
      {smsReason && (
        <Alert tone="y">
          SMS delivery is unavailable: {smsReason} Alerts set to SMS will not be
          sent until a provider is configured.
        </Alert>
      )}

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
        <div className="rounded-card border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
          Loading…
        </div>
      ) : rows.length === 0 ? (
        <div className="rounded-card border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
          No alert types are available for your products.
        </div>
      ) : (
        <div className="space-y-3">
          {rows.map(({ key, meta, configured }) => {
            const row = rowState(key);
            return (
              <Card key={key}>
                <CardContent className="space-y-3 pt-6">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h2 className={SECTION_TITLE}>
                        {meta.label}
                        {!configured && (
                          <span className="ml-2 align-middle text-[10px] font-semibold uppercase tracking-label text-muted-soft">
                            Not configured
                          </span>
                        )}
                      </h2>
                      <p className="text-xs text-muted">{meta.description}</p>
                    </div>
                    <label className="flex shrink-0 cursor-pointer items-center gap-2 text-xs text-muted">
                      <Checkbox
                        checked={row.enabled}
                        onChange={(e) => update(key, { enabled: e.target.checked })}
                      />
                      Enabled
                    </label>
                  </div>

                  <div className="flex flex-wrap gap-3">
                    {ALL_ROLES.map((role) => (
                      <label
                        key={role}
                        className="flex cursor-pointer items-center gap-1.5 text-xs text-muted"
                      >
                        <Checkbox
                          checked={row.roles.includes(role)}
                          onChange={() => toggleRole(key, role)}
                        />
                        {ROLE_LABELS[role]}
                      </label>
                    ))}
                  </div>
                  <p className="text-[11px] text-muted-soft">
                    Leave every role unchecked to notify administrators and owners.
                  </p>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted">Channel:</span>
                    <Select
                      value={row.channel}
                      onChange={(e) =>
                        update(key, { channel: e.target.value as AlertChannel })
                      }
                      className="w-44"
                    >
                      {ALERT_CHANNEL_OPTIONS.map((o) => (
                        <option
                          key={o.value}
                          value={o.value}
                          // Disabled rather than hidden: an admin who already
                          // selected SMS must still see what their row is set to.
                          disabled={unavailable.has(o.value) && row.channel !== o.value}
                        >
                          {o.label}
                          {unavailable.has(o.value) ? ' (unavailable)' : ''}
                        </option>
                      ))}
                    </Select>
                    <Button size="sm" onClick={() => save(key)} disabled={isSaving}>
                      {savedKey === key ? 'Saved' : 'Save'}
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
