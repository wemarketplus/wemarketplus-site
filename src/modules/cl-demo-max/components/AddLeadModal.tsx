import { useState } from 'react';
import { Field, FI } from '@/shared/cl-demo';
import { ModalShell } from './ModalShell';
import { LEAD_ASSIGNED_OPTS, LEAD_CARE_OPTS, LEAD_SOURCE_OPTS, LEAD_STAGE_OPTS, LEAD_URGENCY_OPTS } from '../constants/maxForms';
import { useMaxDemo } from '../hooks/useMaxDemo';
import type { Urgency } from '../types/maxTypes';

// Reproduces the reference Add Lead modal (saveNewLead).
export function AddLeadModal() {
  const { actions } = useMaxDemo();
  const [f, setF] = useState({ name: '', phone: '', email: '', care: LEAD_CARE_OPTS[0], source: LEAD_SOURCE_OPTS[0], budget: '', urgency: 'High', stage: 'Inquiry', timeline: '', tourdate: '', followdate: new Date(Date.now() + 2 * 86400000).toISOString().split('T')[0], assigned: LEAD_ASSIGNED_OPTS[0], notes: '' });
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));

  const save = () => {
    if (!f.name.trim()) { actions.toast('Prospect name is required', true); return; }
    actions.addLead({ name: f.name.trim(), care: f.care, status: f.stage, urgency: f.urgency as Urgency, source: f.source, phone: f.phone, fu: f.followdate, notes: f.notes });
  };

  return (
    <ModalShell title="+ Add New Lead" subtitle="Lead will appear in pipeline, dashboard, and referral tracking" borderColor="rgba(61,158,232,.35)" maxWidth="sm:max-w-[640px]" saveLabel="💾 Save Lead + Add to Pipeline" onSave={save}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Prospect Name *" wide><input className={FI} placeholder="Dorothy Harrison" value={f.name} onChange={(e) => set('name', e.target.value)} /></Field>
        <Field label="Phone"><input className={FI} type="tel" placeholder="(214) 555-0100" value={f.phone} onChange={(e) => set('phone', e.target.value)} /></Field>
        <Field label="Email"><input className={FI} type="email" placeholder="contact@email.com" value={f.email} onChange={(e) => set('email', e.target.value)} /></Field>
        <Field label="Care Level *"><select className={FI} value={f.care} onChange={(e) => set('care', e.target.value)}>{LEAD_CARE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Lead Source"><select className={FI} value={f.source} onChange={(e) => set('source', e.target.value)}>{LEAD_SOURCE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Budget Range"><input className={FI} placeholder="$3,000–$4,500/mo" value={f.budget} onChange={(e) => set('budget', e.target.value)} /></Field>
        <Field label="Urgency"><select className={FI} value={f.urgency} onChange={(e) => set('urgency', e.target.value)}>{LEAD_URGENCY_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Pipeline Stage"><select className={FI} value={f.stage} onChange={(e) => set('stage', e.target.value)}>{LEAD_STAGE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Move-In Timeline"><input className={FI} placeholder="30 days" value={f.timeline} onChange={(e) => set('timeline', e.target.value)} /></Field>
        <Field label="Tour Date"><input className={FI} type="date" value={f.tourdate} onChange={(e) => set('tourdate', e.target.value)} /></Field>
        <Field label="Follow-Up Date"><input className={FI} type="date" value={f.followdate} onChange={(e) => set('followdate', e.target.value)} /></Field>
        <Field label="Assigned To"><select className={FI} value={f.assigned} onChange={(e) => set('assigned', e.target.value)}>{LEAD_ASSIGNED_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Notes" wide><textarea className={`${FI} min-h-[72px]`} rows={3} placeholder="Initial inquiry details, family notes, urgency context…" value={f.notes} onChange={(e) => set('notes', e.target.value)} /></Field>
      </div>
    </ModalShell>
  );
}
