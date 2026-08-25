import { useState } from 'react';
import { Field, FI } from '@/shared/cl-demo';
import { ModalShell } from './ModalShell';
import { SOURCE_ASSIGNED_OPTS, SOURCE_STATUS_OPTS, SOURCE_TYPE_OPTS } from '../constants/maxForms';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces the reference Add Referral Source modal (saveNewSource).
export function AddSourceModal() {
  const { actions } = useMaxDemo();
  const [f, setF] = useState({ name: '', org: '', title: '', phone: '', email: '', type: SOURCE_TYPE_OPTS[0], status: SOURCE_STATUS_OPTS[0], assigned: SOURCE_ASSIGNED_OPTS[0], paid: false, notes: '' });
  const set = (k: string, v: string | boolean) => setF((p) => ({ ...p, [k]: v }));

  const save = () => {
    if (!f.name.trim()) { actions.toast('Contact name is required', true); return; }
    actions.addRefSource({ name: f.name.trim(), org: f.org, type: f.type + (f.paid ? ' (Paid)' : '') });
  };

  return (
    <ModalShell title="+ Add Referral Source" subtitle="Source will appear in lead dropdowns, activity notes, and ROI tracking" borderColor="rgba(167,139,250,.35)" maxWidth="sm:max-w-[580px]" saveLabel="💾 Save Referral Source" onSave={save}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Contact Name *" wide><input autoComplete="off" className={FI} placeholder="Dr. Amanda Chen" value={f.name} onChange={(e) => set('name', e.target.value)} /></Field>
        <Field label="Organization / Facility"><input autoComplete="off" className={FI} placeholder="Baylor Medical Center" value={f.org} onChange={(e) => set('org', e.target.value)} /></Field>
        <Field label="Title / Role"><input autoComplete="off" className={FI} placeholder="Physician" value={f.title} onChange={(e) => set('title', e.target.value)} /></Field>
        <Field label="Phone"><input autoComplete="off" className={FI} type="tel" placeholder="(214) 555-0100" value={f.phone} onChange={(e) => set('phone', e.target.value)} /></Field>
        <Field label="Email"><input autoComplete="off" className={FI} type="email" placeholder="dr.chen@baylor.com" value={f.email} onChange={(e) => set('email', e.target.value)} /></Field>
        <Field label="Referral Type"><select autoComplete="off" className={FI} value={f.type} onChange={(e) => set('type', e.target.value)}>{SOURCE_TYPE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Relationship Status"><select autoComplete="off" className={FI} value={f.status} onChange={(e) => set('status', e.target.value)}>{SOURCE_STATUS_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Assigned Marketer"><select autoComplete="off" className={FI} value={f.assigned} onChange={(e) => set('assigned', e.target.value)}>{SOURCE_ASSIGNED_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <label className="flex cursor-pointer items-center gap-2.5 rounded-[8px] border border-[#f59e0b]/20 bg-[#f59e0b]/[0.06] p-2.5 sm:col-span-2">
          <input type="checkbox" checked={f.paid} onChange={(e) => set('paid', e.target.checked)} className="h-4 w-4 accent-[#f59e0b]" />
          <span className="text-[12px] font-bold text-[#f59e0b]">This is a PAID referral source (APFM, Caring.com, etc.)</span>
        </label>
        <Field label="Notes" wide><textarea autoComplete="off" className={`${FI} min-h-[56px]`} rows={2} placeholder="Relationship history, visit frequency, referral volume…" value={f.notes} onChange={(e) => set('notes', e.target.value)} /></Field>
      </div>
    </ModalShell>
  );
}
