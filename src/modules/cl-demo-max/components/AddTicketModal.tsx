import { useState } from 'react';
import { Field, FI } from '@/shared/cl-demo';
import { ModalShell } from './ModalShell';
import { TICKET_ASSIGNED_OPTS, TICKET_PRIORITY_OPTS, TICKET_SERVICE_OPTS, TICKET_STATUS_OPTS } from '../constants/maxForms';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces the reference New Maintenance Ticket modal (saveNewTicket).
export function AddTicketModal() {
  const { apts, actions } = useMaxDemo();
  const [f, setF] = useState({ unit: 'Common', type: TICKET_SERVICE_OPTS[0], priority: 'Medium', assignee: TICKET_ASSIGNED_OPTS[0], issue: '', due: new Date(Date.now() + 3 * 86400000).toISOString().split('T')[0], status: 'open', desc: '' });
  const set = (k: string, v: string) => setF((p) => ({ ...p, [k]: v }));

  const save = () => {
    if (!f.issue.trim()) { actions.toast('Issue summary is required', true); return; }
    actions.addMaint({ unit: f.unit, type: f.type, issue: f.issue.trim(), priority: f.priority, assignee: f.assignee, status: f.status });
  };

  return (
    <ModalShell title="+ New Maintenance Ticket" subtitle="Ticket auto-populates maintenance board, make-ready workflow, and assigned tasks" borderColor="rgba(248,113,113,.35)" maxWidth="sm:max-w-[580px]" saveLabel="💾 Create Ticket" onSave={save}>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Unit Number *"><select autoComplete="off" className={FI} value={f.unit} onChange={(e) => set('unit', e.target.value)}><option value="Common">Common Area</option>{apts.map((a) => <option key={a.id} value={a.unit}>Unit {a.unit}{a.resident ? ' — ' + a.resident : ''}</option>)}</select></Field>
        <Field label="Service Type"><select autoComplete="off" className={FI} value={f.type} onChange={(e) => set('type', e.target.value)}>{TICKET_SERVICE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Priority"><select autoComplete="off" className={FI} value={f.priority} onChange={(e) => set('priority', e.target.value)}>{TICKET_PRIORITY_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Assigned To"><select autoComplete="off" className={FI} value={f.assignee} onChange={(e) => set('assignee', e.target.value)}>{TICKET_ASSIGNED_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Issue Summary *" wide><input autoComplete="off" className={FI} placeholder="Describe the issue briefly" value={f.issue} onChange={(e) => set('issue', e.target.value)} /></Field>
        <Field label="Due Date"><input autoComplete="off" className={FI} type="date" value={f.due} onChange={(e) => set('due', e.target.value)} /></Field>
        <Field label="Status"><select autoComplete="off" className={FI} value={f.status} onChange={(e) => set('status', e.target.value)}>{TICKET_STATUS_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <Field label="Full Description" wide><textarea autoComplete="off" className={`${FI} min-h-[72px]`} rows={3} placeholder="Detailed description, location within unit, photos context…" value={f.desc} onChange={(e) => set('desc', e.target.value)} /></Field>
      </div>
    </ModalShell>
  );
}
