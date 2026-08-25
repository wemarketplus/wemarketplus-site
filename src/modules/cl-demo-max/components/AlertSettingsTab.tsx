import { useState } from 'react';
import { Card, DemoButton, FI } from '@/shared/cl-demo';
import { ALERT_CHANNELS, ALERT_DEFS, ALERT_ROLES } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import type { AlertSetting } from '../types/maxTypes';

// Reproduces rAlertSettings(): per-alert enable toggle, role targeting, and
// delivery channel, each with its own Save.
export function AlertSettingsTab() {
  const { alerts, actions } = useMaxDemo();
  const [draft, setDraft] = useState<Record<string, AlertSetting>>(() => JSON.parse(JSON.stringify(alerts)));

  const update = (key: string, patch: Partial<AlertSetting>) => setDraft((d) => ({ ...d, [key]: { ...d[key], ...patch } }));
  const toggleRole = (key: string, role: string) => {
    const roles = draft[key].roles.includes(role) ? draft[key].roles.filter((r) => r !== role) : [...draft[key].roles, role];
    update(key, { roles });
  };

  return (
    <div className="flex flex-col gap-3">
      {ALERT_DEFS.map((at) => {
        const s = draft[at.key];
        return (
          <Card key={at.key} title={<div><div className="text-[13px] font-extrabold text-[#f4f8ff]">{at.label}</div><div className="text-[11px] text-[#6b7fa3]">{at.desc}</div></div>} action={<label className="flex cursor-pointer items-center gap-2"><input type="checkbox" checked={s.enabled} onChange={(e) => update(at.key, { enabled: e.target.checked })} className="h-4 w-4 accent-[#f59e0b]" /><span className="text-[12px] text-[#8ba4c4]">Enabled</span></label>}>
            <div className="flex flex-wrap gap-2.5">
              {ALERT_ROLES.map((role) => (
                <label key={role} className="flex cursor-pointer items-center gap-1.5 text-[12px]"><input type="checkbox" checked={s.roles.includes(role)} onChange={() => toggleRole(at.key, role)} className="accent-[#f59e0b]" />{role}</label>
              ))}
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-[11px] text-[#6b7fa3]">Channel:</span>
              <select autoComplete="off" className={`${FI} w-[120px]`} value={s.channel} onChange={(e) => update(at.key, { channel: e.target.value })}>{ALERT_CHANNELS.map((ch) => <option key={ch} value={ch}>{ch}</option>)}</select>
              <DemoButton sm onClick={() => actions.saveAlert(at.key, draft[at.key])}>Save</DemoButton>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
