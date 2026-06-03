import { useState } from 'react';
import { Field, FI } from '@/shared/cl-demo';
import { ModalShell } from './ModalShell';
import { MR_ASSIGNED_OPTS, MR_TASK_OPTS } from '../constants/maxForms';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces the reference New Make-Ready Ticket modal (saveNewMR).
export function AddMrModal() {
  const { apts, actions } = useMaxDemo();
  const [unit, setUnit] = useState('');
  const [moveout, setMoveout] = useState(new Date(Date.now() + 7 * 86400000).toISOString().split('T')[0]);
  const [target, setTarget] = useState(new Date(Date.now() + 14 * 86400000).toISOString().split('T')[0]);
  const [assignee, setAssignee] = useState(MR_ASSIGNED_OPTS[0]);
  const [tasks, setTasks] = useState<string[]>([...MR_TASK_OPTS]);

  const toggle = (t: string) => setTasks((p) => (p.includes(t) ? p.filter((x) => x !== t) : [...p, t]));
  const save = () => {
    if (!unit) { actions.toast('Select a unit', true); return; }
    actions.addMr({ unit, moveout, target, assignee, tasks });
  };

  return (
    <ModalShell title="+ New Make-Ready Ticket" subtitle="Auto-creates task checklist and syncs to make-ready board" borderColor="rgba(245,158,11,.35)" maxWidth="sm:max-w-[540px]" saveLabel="💾 Create Make-Ready Ticket" onSave={save}>
      <div className="flex flex-col gap-3">
        <Field label="Unit Number *"><select className={FI} value={unit} onChange={(e) => setUnit(e.target.value)}><option value="">Select unit…</option>{apts.filter((a) => a.status !== 'occupied').map((a) => <option key={a.id} value={a.unit}>{a.unit}</option>)}</select></Field>
        <Field label="Move-Out Date"><input className={FI} type="date" value={moveout} onChange={(e) => setMoveout(e.target.value)} /></Field>
        <Field label="Target Ready Date"><input className={FI} type="date" value={target} onChange={(e) => setTarget(e.target.value)} /></Field>
        <Field label="Assigned To"><select className={FI} value={assignee} onChange={(e) => setAssignee(e.target.value)}>{MR_ASSIGNED_OPTS.map((o) => <option key={o}>{o}</option>)}</select></Field>
        <div className="flex flex-col gap-1">
          <div className="text-[11px] font-bold text-[#4b6278]">Make-Ready Tasks</div>
          <div className="flex flex-col gap-1.5 rounded-[8px] border border-white/[0.08] bg-[#060e1b] p-3">
            {MR_TASK_OPTS.map((t) => (
              <label key={t} className="flex cursor-pointer items-center gap-2 text-[12px]"><input type="checkbox" checked={tasks.includes(t)} onChange={() => toggle(t)} className="h-3.5 w-3.5 accent-[#f59e0b]" />{t}</label>
            ))}
          </div>
        </div>
      </div>
    </ModalShell>
  );
}
