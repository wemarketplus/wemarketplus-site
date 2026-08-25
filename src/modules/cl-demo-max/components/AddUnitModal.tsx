import { useState } from 'react';
import { Field, FI } from '@/shared/cl-demo';
import { ModalShell } from './ModalShell';
import { UNIT_CARE_OPTS, UNIT_STATUS_OPTS, UNIT_TYPE_OPTS } from '../constants/maxForms';
import { useMaxDemo } from '../hooks/useMaxDemo';
import type { AptStatus } from '../types/maxTypes';

// Reproduces the reference Add Unit modal (saveNewUnit).
export function AddUnitModal() {
  const { actions } = useMaxDemo();
  const [f, setF] = useState({ unit: '', type: UNIT_TYPE_OPTS[1], sqft: '', care: UNIT_CARE_OPTS[0], status: 'available', rate: '', resident: '', notes: '' });
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));

  const save = () => {
    if (!f.unit.trim()) { actions.toast('Unit number is required', true); return; }
    actions.addApt({ unit: f.unit.trim(), type: f.type, care: f.care, sqft: parseInt(f.sqft) || 0, status: f.status as AptStatus, resident: f.resident, rate: parseFloat(f.rate) || 0 });
  };

  return (
    <ModalShell title="+ Add Apartment Unit" subtitle="Unit will sync to inventory, financial ledger, and occupancy dashboard" borderColor="rgba(79,200,122,.35)" maxWidth="sm:max-w-[620px]" saveLabel="💾 Save Unit + Sync to Ledger" onSave={save}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Unit Number *"><input autoComplete="off" className={FI} placeholder="101" value={f.unit} onChange={(e) => set('unit', e.target.value)} /></Field>
        <Field label="Floor Plan"><select autoComplete="off" className={FI} value={f.type} onChange={(e) => set('type', e.target.value)}>{UNIT_TYPE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Square Footage"><input autoComplete="off" className={FI} type="number" placeholder="650" value={f.sqft} onChange={(e) => set('sqft', e.target.value)} /></Field>
        <Field label="Care Level"><select autoComplete="off" className={FI} value={f.care} onChange={(e) => set('care', e.target.value)}>{UNIT_CARE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Occupancy Status"><select autoComplete="off" className={FI} value={f.status} onChange={(e) => set('status', e.target.value)}>{UNIT_STATUS_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Monthly Rent ($)"><input autoComplete="off" className={FI} type="number" placeholder="3500" value={f.rate} onChange={(e) => set('rate', e.target.value)} /></Field>
        <Field label="Current Resident"><input autoComplete="off" className={FI} value={f.resident} onChange={(e) => set('resident', e.target.value)} /></Field>
        <Field label="Notes" wide><textarea autoComplete="off" className={`${FI} min-h-[56px]`} rows={2} placeholder="Unit notes, special features, maintenance history…" value={f.notes} onChange={(e) => set('notes', e.target.value)} /></Field>
      </div>
      <div className="mt-3 rounded-[8px] border border-[#f59e0b]/20 bg-[#f59e0b]/[0.06] p-3 text-[12px] text-[#f59e0b]">🔒 Only Executive Director and Admin can edit rent, market value, and financial data. All changes are audit-logged.</div>
    </ModalShell>
  );
}
