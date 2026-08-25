import { useState } from 'react';
import { Badge, Card, DemoButton, Field, FG, FI } from '@/shared/cl-demo';
import { PRIORITY_COLOR } from '../constants/clDemoNav';
import { useClDemo } from '../hooks/useClDemo';
import { openTasks } from '../utils/clDemoFormat';
import type { TaskPriority } from '../types/clDemoTypes';

// Task Manager tab — reproduces rTasks(): open/complete counts, inline add
// form, toggle + admin delete.
export function TasksTab() {
  const { tasks, role, taskFormOpen, actions } = useClDemo();
  const [title, setTitle] = useState('');
  const [due, setDue] = useState('');
  const [priority, setPriority] = useState<TaskPriority>('Med');
  const [assignee, setAssignee] = useState('');

  const open = openTasks(tasks).length;
  const done = tasks.filter((t) => t.done).length;

  const save = () => {
    if (!title.trim()) {
      actions.toast('Title required.', true);
      return;
    }
    actions.addTask({ title: title.trim(), due: due || 'TBD', priority, assignee: assignee || '—' });
    actions.toast('Task added: ' + title.trim());
    setTitle('');
    setDue('');
    setAssignee('');
  };

  return (
    <Card
      title="Task Manager"
      action={
        <DemoButton sm onClick={() => actions.setTaskForm(true)}>
          + Add Task
        </DemoButton>
      }
    >
      {taskFormOpen && (
        <div className="mb-[14px] rounded-[10px] border border-[#f59e0b]/15 bg-[#071120] p-[14px]">
          <div className={FG}>
            <Field label="Task Title *" wide>
              <input autoComplete="off" className={FI} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Follow up with Dorothy Harrison" />
            </Field>
            <Field label="Due Date">
              <input autoComplete="off" className={FI} type="date" value={due} onChange={(e) => setDue(e.target.value)} />
            </Field>
            <Field label="Priority">
              <select autoComplete="off" className={FI} value={priority} onChange={(e) => setPriority(e.target.value as TaskPriority)}>
                <option value="High">High</option>
                <option value="Med">Medium</option>
                <option value="Low">Low</option>
              </select>
            </Field>
            <Field label="Assignee" wide>
              <input autoComplete="off" className={FI} value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="Sarah M." />
            </Field>
          </div>
          <div className="flex gap-2">
            <DemoButton sm onClick={save}>Add Task</DemoButton>
            <DemoButton variant="x" sm onClick={() => actions.setTaskForm(false)}>Cancel</DemoButton>
          </div>
        </div>
      )}

      <div className="mb-2.5 flex gap-1.5">
        <Badge tone="red">{open} open</Badge>
        <Badge tone="green">{done} complete</Badge>
      </div>

      {tasks.map((t) => (
        <div
          key={t.id}
          className={`mb-[7px] flex items-center gap-[11px] rounded-[10px] border border-white/[0.05] bg-[#071120] px-[13px] py-[11px] ${t.done ? 'opacity-50' : ''}`}
        >
          <input
            type="checkbox"
            checked={t.done}
            onChange={(e) => { actions.toggleTask(t.id, e.target.checked); actions.toast(e.target.checked ? 'Task completed!' : 'Task reopened.'); }}
            className="h-3.5 w-3.5 flex-shrink-0 accent-[#f59e0b]"
          />
          <div className="flex-1">
            <div className={`text-[13px] text-[#f4f8ff] ${t.done ? 'line-through' : ''}`}>{t.title}</div>
            <div className="mt-0.5 text-[10px] text-[#4b6278]">
              Due {t.due} • <span className={PRIORITY_COLOR[t.priority]}>{t.priority}</span> • {t.assignee}
            </div>
          </div>
          {role === 'admin' && (
            <DemoButton variant="r" sm onClick={() => { actions.deleteTask(t.id); actions.toast('Task removed.'); }}>✕</DemoButton>
          )}
        </div>
      ))}
    </Card>
  );
}
