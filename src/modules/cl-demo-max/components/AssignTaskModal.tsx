import { useState } from 'react';
import { Field, FI } from '@/shared/cl-demo';
import { ModalShell } from './ModalShell';
import { ASSIGN_TASK_ASSIGNEE_OPTS, ASSIGN_TASK_PRIORITY_OPTS, ASSIGN_TASK_TYPE_OPTS } from '../constants/maxForms';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces the reference Assign Task modal (saveNewTask), shared by the
// housekeeping "+ Assign Task" and tasks "+ Add Task" triggers.
export function AssignTaskModal() {
  const { actions } = useMaxDemo();
  const [f, setF] = useState({ task: '', assignee: ASSIGN_TASK_ASSIGNEE_OPTS[0], type: ASSIGN_TASK_TYPE_OPTS[0], priority: 'Normal', due: new Date(Date.now() + 86400000).toISOString().split('T')[0], related: '', notes: '', calendar: true });
  const set = (k: string, v: string | boolean) => setF((p) => ({ ...p, [k]: v }));

  const save = () => {
    if (!f.task.trim()) { actions.toast('Task title is required', true); return; }
    actions.addAssignTask({ task: f.task.trim(), assignee: f.assignee, type: f.type, priority: f.priority, unit: f.related, due: f.due });
  };

  return (
    <ModalShell title="+ Assign Task" subtitle="Task appears in user dashboard, calendar, and task list" borderColor="rgba(167,139,250,.35)" maxWidth="sm:max-w-[540px]" saveLabel="💾 Assign Task" onSave={save}>
      <div className="flex flex-col gap-3">
        <Field label="Task Title *"><input className={FI} placeholder="Deep clean Unit 204 — move-out turnover" value={f.task} onChange={(e) => set('task', e.target.value)} /></Field>
        <Field label="Assign To"><select className={FI} value={f.assignee} onChange={(e) => set('assignee', e.target.value)}>{ASSIGN_TASK_ASSIGNEE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Task Type"><select className={FI} value={f.type} onChange={(e) => set('type', e.target.value)}>{ASSIGN_TASK_TYPE_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Priority"><select className={FI} value={f.priority} onChange={(e) => set('priority', e.target.value)}>{ASSIGN_TASK_PRIORITY_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Due Date"><input className={FI} type="date" value={f.due} onChange={(e) => set('due', e.target.value)} /></Field>
          <Field label="Related Unit / Lead"><input className={FI} placeholder="Unit 204, Dorothy H., etc." value={f.related} onChange={(e) => set('related', e.target.value)} /></Field>
        </div>
        <Field label="Notes"><textarea className={`${FI} min-h-[56px]`} rows={2} placeholder="Task details, special instructions…" value={f.notes} onChange={(e) => set('notes', e.target.value)} /></Field>
        <label className="flex cursor-pointer items-center gap-2.5"><input type="checkbox" checked={f.calendar} onChange={(e) => set('calendar', e.target.checked)} className="h-4 w-4 accent-[#f59e0b]" /><span className="text-[12px] text-[#c8d6e8]">Add to calendar if due date is set</span></label>
      </div>
    </ModalShell>
  );
}
