import { useMemo, useState } from 'react';
import { Button, Card, CardContent, Input } from '@/shared/ui/core';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { FINANCIAL_SETTING_DEFS } from '../constants/adminSettingsConstants';
import { useListFinancialSettingsQuery, useUpsertFinancialSettingMutation } from '../api/adminSettingsApi';

// Financial Settings (Admin-only, Max tier): reimbursement/compliance rates.
// Changes apply immediately to new records; historical records retain the
// rate that was live when they were logged.
export function FinancialSettingsPage() {
  const { data, isLoading, error } = useListFinancialSettingsQuery();
  const [upsert, { isLoading: isSaving, error: saveError }] = useUpsertFinancialSettingMutation();
  const [savedKey, setSavedKey] = useState<string | null>(null);

  const byKey = useMemo(() => new Map(data?.map((s) => [s.settingKey, s.settingValue]) ?? []), [data]);
  const [draft, setDraft] = useState<Record<string, string>>({});

  const valueFor = (key: string, fallback: string) => draft[key] ?? byKey.get(key) ?? fallback;

  const save = async (key: string, fallback: string) => {
    await upsert({ settingKey: key, settingValue: valueFor(key, fallback) }).unwrap();
    setSavedKey(key);
    setTimeout(() => setSavedKey((k) => (k === key ? null : k)), 2000);
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Financial settings</h1>
        <p className="text-sm text-muted">Reimbursement and compliance rates.</p>
      </header>

      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
          Failed to load financial settings.
        </p>
      )}
      {saveError && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
          {extractApiErrorMessage(saveError, 'Failed to save setting')}
        </p>
      )}

      {isLoading ? (
        <div className="rounded-[12px] border border-white/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
          Loading…
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardContent className="space-y-5 pt-6">
              {FINANCIAL_SETTING_DEFS.map((s) => (
                <div key={s.key}>
                  <p className="mb-0.5 text-xs font-bold text-foreground">{s.label}</p>
                  <p className="mb-1.5 text-[11px] text-muted-soft">{s.hint}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-muted">$</span>
                    <Input
                      className="max-w-[120px]"
                      value={valueFor(s.key, s.defaultValue)}
                      onChange={(e) => setDraft((d) => ({ ...d, [s.key]: e.target.value }))}
                    />
                    <span className="text-xs text-muted">{s.suffix}</span>
                    <Button size="sm" onClick={() => save(s.key, s.defaultValue)} disabled={isSaving}>
                      {savedKey === s.key ? 'Saved' : 'Save'}
                    </Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-[12px] leading-[1.8] text-muted">
              <p>• <strong className="text-foreground">Mileage rate</strong> — per-mile reimbursement rate</p>
              <p>• <strong className="text-foreground">Gift/gratuity limit</strong> — max value per visit</p>
              <p>• Changes apply immediately to new records</p>
              <p>• Historical records retain the rate logged at the time</p>
              <p className="mt-2.5 rounded-md border border-success/30 bg-success/10 px-3 py-2 text-[11px] text-success">
                Admin-only access. All changes are audit logged.
              </p>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
