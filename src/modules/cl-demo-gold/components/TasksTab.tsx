import { useState } from 'react';
import { Card, DemoButton, Field, FI } from '@/shared/cl-demo';
import { TASK_PRIORITY_COLOR } from '../constants/goldStatus';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { taskRowClass } from '../utils/goldFormat';
import type { TaskPriority } from '../types/goldTypes';

// Reproduces rTasks(): a task list with checkbox toggle + delete, and an inline
// "Add Task" form.
export function TasksTab() {
  const { tasks, taskFormOpen, actions } = useGoldDemo();
  const [title, setTitle] = useState('');
  const [due, setDue] = useState('');
  const [priority, setPriority] = useState<TaskPriority>('Med');

  const submit = () => {
    if (!title.trim()) {
      actions.toast('Title required.', true);
      return;
    }
    actions.addTask({ title: title.trim(), due: due || 'TBD', priority });
    setTitle('');
    setDue('');
    setPriority('Med');
  };

  return (
    <Card
      title="Task Manager"
      action={<DemoButton sm onClick={() => actions.setTaskForm(true)}>+ Add Task</DemoButton>}
    >
      {taskFormOpen && (
        <div className="mb-3 rounded-[10px] border border-[#f59e0b]/15 bg-[#071120] p-[14px]">
          <div className="mb-3 grid grid-cols-2 gap-3">
            <Field label="Title *" wide>
              <input className={FI} placeholder="Task title" value={title} onChange={(e) => setTitle(e.target.value)} />
            </Field>
            <Field label="Due Date">
              <input className={FI} type="date" value={due} onChange={(e) => setDue(e.target.value)} />
            </Field>
            <Field label="Priority">
              <select className={FI} value={priority} onChange={(e) => setPriority(e.target.value as TaskPriority)}>
                <option value="High">High</option>
                <option value="Med">Medium</option>
                <option value="Low">Low</option>
              </select>
            </Field>
          </div>
          <div className="flex gap-2">
            <DemoButton sm onClick={submit}>Add</DemoButton>
            <DemoButton variant="x" sm onClick={() => actions.setTaskForm(false)}>Cancel</DemoButton>
          </div>
        </div>
      )}

      {tasks.map((t) => (
        <div
          key={t.id}
          className={taskRowClass(t.done)}
        >
          <input
            type="checkbox"
            checked={t.done}
            onChange={(e) => actions.toggleTask(t.id, e.target.checked)}
            className="h-3.5 w-3.5 flex-shrink-0 accent-[#f59e0b]"
          />
          <div className="flex-1">
            <div className={`text-[13px] text-[#f4f8ff] ${t.done ? 'line-through' : ''}`}>{t.title}</div>
            <div className="text-[10px] text-[#4b6278]">
              Due {t.due} • <span style={{ color: TASK_PRIORITY_COLOR[t.priority] }}>{t.priority}</span>
            </div>
          </div>
          <DemoButton variant="r" sm onClick={() => actions.deleteTask(t.id)}>✕</DemoButton>
        </div>
      ))}
    </Card>
  );
}
