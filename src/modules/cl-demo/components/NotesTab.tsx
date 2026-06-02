import { useState } from 'react';
import { Card } from './Card';
import { DemoButton } from './DemoButton';
import { Field } from './Field';
import { NOTE_CONTACT_TYPES } from '../constants/clDemoData';
import { FI } from '../constants/clDemoStyles';
import { useClDemo } from '../hooks/useClDemo';

function todayIso(): string {
  return new Date().toISOString().split('T')[0];
}

// Activity Notes tab — reproduces rNotes(): a log-note form beside an activity
// feed of saved notes.
export function NotesTab() {
  const { leads, notes, actions } = useClDemo();
  const [leadId, setLeadId] = useState('');
  const [contact, setContact] = useState<string>(NOTE_CONTACT_TYPES[0]);
  const [summary, setSummary] = useState('');
  const [next, setNext] = useState('');

  const save = () => {
    if (!summary.trim()) {
      actions.toast('Summary required.', true);
      return;
    }
    actions.addNote({ leadId: leadId ? parseInt(leadId, 10) : null, contact, summary: summary.trim(), next, date: todayIso() });
    actions.toast('Note saved!');
    setSummary('');
    setNext('');
  };

  return (
    <div className="grid grid-cols-1 gap-[14px] lg:[grid-template-columns:1fr_1.4fr]">
      <Card title="Log Note">
        <Field label="Lead / Prospect" className="mb-2.5">
          <select className={FI} value={leadId} onChange={(e) => setLeadId(e.target.value)}>
            <option value="">— General Note —</option>
            {leads.map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}
          </select>
        </Field>
        <Field label="Contact Type" className="mb-2.5">
          <select className={FI} value={contact} onChange={(e) => setContact(e.target.value)}>
            {NOTE_CONTACT_TYPES.map((c) => <option key={c}>{c}</option>)}
          </select>
        </Field>
        <Field label="Summary *" className="mb-2.5">
          <textarea className={`${FI} min-h-[72px] resize-y`} rows={3} value={summary} onChange={(e) => setSummary(e.target.value)} placeholder="What happened? Key takeaways…" />
        </Field>
        <Field label="Next Step" className="mb-2.5">
          <input className={FI} value={next} onChange={(e) => setNext(e.target.value)} placeholder="Schedule tour, send proposal…" />
        </Field>
        <DemoButton onClick={save}>Save Note</DemoButton>
      </Card>

      <Card title="Activity Feed">
        <div className="flex flex-col gap-2.5">
          {notes.map((n) => {
            const lead = leads.find((l) => l.id === n.leadId);
            return (
              <div key={n.id} className="rounded-[10px] border border-white/[0.05] bg-[#071120] p-3">
                <div className="mb-1.5 flex justify-between">
                  <div className="text-[13px] font-bold text-[#f4f8ff]">{lead ? lead.name : 'General'}</div>
                  <div className="text-[10px] text-[#4b6278]">{n.date} • {n.contact}</div>
                </div>
                <div className="mb-1.5 text-[12px] leading-relaxed text-[#c8d6e8]">{n.summary}</div>
                <div className="text-[11px] text-[#f59e0b]">Next: {n.next}</div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
