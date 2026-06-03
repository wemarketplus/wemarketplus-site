import { useState } from 'react';
import { Card, DemoButton, Field, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { GIFT_TYPES } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rGiftGratuity(): a gift-log form with live limit warning, plus a
// compliance summary and recent logs.
export function GiftTab() {
  const { giftLogs, giftLimit, actions } = useMaxDemo();
  const [recipient, setRecipient] = useState('');
  const [facility, setFacility] = useState('');
  const [date, setDate] = useState('');
  const [type, setType] = useState('');
  const [value, setValue] = useState('');
  const [purpose, setPurpose] = useState('');

  const val = parseFloat(value) || 0;
  const over = val > giftLimit;
  const totalVal = giftLogs.reduce((s, l) => s + l.gift_value, 0);
  const violations = giftLogs.filter((l) => !l.compliance_ok).length;

  const save = () => {
    if (!recipient.trim() || !date || !type || !value) { actions.toast('Fill all required fields (*)', true); return; }
    if (over && !window.confirm('Value exceeds $' + giftLimit + ' limit. Save anyway?')) return;
    actions.addGiftLog({ recipient_name: recipient.trim(), facility_name: facility, gift_type: type, gift_value: val, visit_date: date, compliance_ok: val <= giftLimit }, val <= giftLimit);
    setRecipient(''); setFacility(''); setDate(''); setType(''); setValue(''); setPurpose('');
  };

  return (
    <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
      <Card title="Log Gift / Gratuity">
        <div className="flex flex-col gap-2.5">
          <div className="rounded-[8px] border border-[#f59e0b]/20 bg-[#f59e0b]/[0.08] px-3 py-2 text-[12px] text-[#f59e0b]">Per-visit limit: <strong>${giftLimit.toFixed(2)}</strong> (Admin can change in Financial Settings)</div>
          <Field label="Recipient Name *"><input className={FI} placeholder="Dr. Smith…" value={recipient} onChange={(e) => setRecipient(e.target.value)} /></Field>
          <Field label="Facility"><input className={FI} placeholder="North Park Rehab" value={facility} onChange={(e) => setFacility(e.target.value)} /></Field>
          <Field label="Visit Date *"><input className={FI} type="date" value={date} onChange={(e) => setDate(e.target.value)} /></Field>
          <Field label="Gift Type *"><select className={FI} value={type} onChange={(e) => setType(e.target.value)}><option value="">Select…</option>{GIFT_TYPES.map((t) => <option key={t}>{t}</option>)}</select></Field>
          <Field label={`Gift Value ($)`}><input className={FI} type="number" step={0.01} placeholder="0.00" value={value} onChange={(e) => setValue(e.target.value)} /></Field>
          {over && <div className="rounded-[8px] border border-[#f87171]/25 bg-[#f87171]/[0.08] px-3 py-2 text-[12px] text-[#f87171]">⚠ Exceeds the ${giftLimit} per-visit limit!</div>}
          <Field label="Visit Purpose"><input className={FI} placeholder="Relationship visit, in-service…" value={purpose} onChange={(e) => setPurpose(e.target.value)} /></Field>
          <DemoButton onClick={save}>💾 Save Gift Log</DemoButton>
        </div>
      </Card>

      <div>
        <Card title="Compliance Summary">
          <div className="flex flex-col">
            <div className="flex justify-between border-b border-white/[0.05] py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Per-Visit Limit</span><span className="font-extrabold text-[#f59e0b]">${giftLimit.toFixed(2)}</span></div>
            <div className="flex justify-between border-b border-white/[0.05] py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Total Logged</span><span className="font-extrabold text-[#f4f8ff]">{giftLogs.length}</span></div>
            <div className="flex justify-between border-b border-white/[0.05] py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Total Value</span><span className="font-extrabold text-[#f4f8ff]">${totalVal.toFixed(2)}</span></div>
            <div className="flex justify-between py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Compliance Violations</span><span className="font-extrabold" style={{ color: violations > 0 ? '#f87171' : '#4fc87a' }}>{violations}</span></div>
          </div>
        </Card>
        <Card title="Recent Logs">
          <div className="overflow-x-auto">
            <table className={TBL}>
              <thead>
                <tr>{['Date', 'Recipient', 'Type', 'Value', 'Status'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
              </thead>
              <tbody>
                {giftLogs.map((l) => (
                  <tr key={l.id} className="hover:bg-white/[0.02]">
                    <td className={`${TD} text-[11px]`}>{l.visit_date}</td>
                    <td className={TD}><div className="font-semibold text-[#f4f8ff]">{l.recipient_name}</div><div className="text-[10px] text-[#4b6278]">{l.facility_name}</div></td>
                    <td className={`${TD} text-[11px]`}>{l.gift_type}</td>
                    <td className={`${TD} font-bold`} style={{ color: l.compliance_ok ? '#4fc87a' : '#f87171' }}>${l.gift_value.toFixed(2)}</td>
                    <td className={TD}><span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-bold ${l.compliance_ok ? 'bg-[#4fc87a]/10 text-[#4fc87a]' : 'bg-[#f87171]/10 text-[#f87171]'}`}>{l.compliance_ok ? 'OK' : 'Over Limit'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}
