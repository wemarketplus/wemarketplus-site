import { useState } from 'react';
import { Card, DemoButton, FI } from '@/shared/cl-demo';
import { FIN_DEFS } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rFinSettings(): editable reimbursement/compliance rates plus an
// explainer card.
export function FinSettingsTab() {
  const { finSettings, actions } = useMaxDemo();
  const [draft, setDraft] = useState<Record<string, string>>({ ...finSettings });

  return (
    <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
      <Card title="Reimbursement & Compliance Rates">
        <div className="flex flex-col gap-[14px]">
          {FIN_DEFS.map((s) => (
            <div key={s.key}>
              <div className="mb-0.5 text-[11px] font-bold text-[#8ba4c4]">{s.label}</div>
              <div className="mb-1.5 text-[10px] text-[#6b7fa3]">{s.hint}</div>
              <div className="flex items-center gap-2">
                <span className="text-[#6b7fa3]">$</span>
                <input className={`${FI} max-w-[120px]`} value={draft[s.key]} onChange={(e) => setDraft((d) => ({ ...d, [s.key]: e.target.value }))} />
                <span className="text-[#6b7fa3]">{s.suffix}</span>
                <DemoButton sm onClick={() => actions.saveFinSetting(s.key, draft[s.key])}>Save</DemoButton>
              </div>
            </div>
          ))}
        </div>
      </Card>
      <Card title="How These Settings Work">
        <div className="text-[12px] leading-[1.8] text-[#8ba4c4]">
          <div>• <strong>Mileage Rate</strong> — per-mile reimbursement rate</div>
          <div>• <strong>Gift/Gratuity Limit</strong> — max per visit, CMS compliance</div>
          <div>• Changes apply immediately to new records</div>
          <div>• Historical records retain the rate logged at that time</div>
          <div className="mt-2.5 rounded-[8px] border border-[#4fc87a]/20 bg-[#4fc87a]/[0.08] p-2.5 text-[11px] text-[#4fc87a]">🔒 Admin-only access. All changes are audit logged.</div>
        </div>
      </Card>
    </div>
  );
}
