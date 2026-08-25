import { useState } from 'react';
import { Card } from '@/shared/cl-demo';
import { DemoButton } from '@/shared/cl-demo';
import { Field } from '@/shared/cl-demo';
import { CARE_LEVELS, LEAD_SOURCES, LEAD_STATUSES, URGENCIES } from '../constants/clDemoData';
import { FG, FI } from '@/shared/cl-demo';
import { useClDemo } from '../hooks/useClDemo';
import type { LeadStatus, Urgency } from '../types/clDemoTypes';

// Add New Lead tab — reproduces the reference rAddLead() form + saveLead().
export function AddLeadTab() {
  const { actions } = useClDemo();
  const [name, setName] = useState('');
  const [phone, setPhone] = useState('');
  const [care, setCare] = useState<string>(CARE_LEVELS[0]);
  const [status, setStatus] = useState<LeadStatus>('Inquiry');
  const [urgency, setUrgency] = useState<Urgency>('Medium');
  const [source, setSource] = useState<string>(LEAD_SOURCES[0]);
  const [fu, setFu] = useState('');
  const [age, setAge] = useState('');
  const [notes, setNotes] = useState('');

  const save = () => {
    if (!name.trim()) {
      actions.toast('Name is required.', true);
      return;
    }
    actions.addLead({ name: name.trim(), phone, care, status, urgency, source, fu, age, notes: notes.trim() });
    actions.toast('Lead saved: ' + name.trim());
    actions.setTab('leads');
  };

  return (
    <Card
      title="New Lead"
      action={
        <DemoButton variant="x" sm onClick={() => actions.setTab('leads')}>
          Cancel
        </DemoButton>
      }
    >
      {/* Own <form> boundary, `autoComplete="off"` — the Status and Care Level
          dropdowns here are app-domain enums a browser profile cannot know, and
          Full Name + `type="tel"` is enough for Chrome to start guessing. These
          fields were also unowned, so the guess extended to every other formless
          control on the tab. See ModalShell for the full note. */}
      <form autoComplete="off" onSubmit={(e) => e.preventDefault()}>
      <div className={FG}>
        <Field label="Full Name *">
          <input autoComplete="off" className={FI} value={name} onChange={(e) => setName(e.target.value)} placeholder="Dorothy Harrison" />
        </Field>
        <Field label="Phone">
          <input autoComplete="off" className={FI} type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="(214) 555-0100" />
        </Field>
        <Field label="Care Level">
          <select autoComplete="off" className={FI} value={care} onChange={(e) => setCare(e.target.value)}>
            {CARE_LEVELS.map((c) => <option key={c}>{c}</option>)}
          </select>
        </Field>
        <Field label="Status">
          <select autoComplete="off" className={FI} value={status} onChange={(e) => setStatus(e.target.value as LeadStatus)}>
            {LEAD_STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Urgency">
          <select autoComplete="off" className={FI} value={urgency} onChange={(e) => setUrgency(e.target.value as Urgency)}>
            {URGENCIES.map((u) => <option key={u} value={u}>{u}</option>)}
          </select>
        </Field>
        <Field label="Referral Source">
          <select autoComplete="off" className={FI} value={source} onChange={(e) => setSource(e.target.value)}>
            {LEAD_SOURCES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Follow-Up Date">
          <input autoComplete="off" className={FI} type="date" value={fu} onChange={(e) => setFu(e.target.value)} />
        </Field>
        <Field label="Age">
          <input autoComplete="off" className={FI} type="number" value={age} onChange={(e) => setAge(e.target.value)} placeholder="82" />
        </Field>
        <Field label="Notes" wide>
          <textarea autoComplete="off" className={`${FI} min-h-[72px] resize-y`} rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Key details, family contacts, budget…" />
        </Field>
      </div>
      <DemoButton onClick={save}>Save Lead</DemoButton>
      </form>
    </Card>
  );
}
