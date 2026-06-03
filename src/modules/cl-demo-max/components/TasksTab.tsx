import { Card, DemoButton } from '@/shared/cl-demo';
import { TASK_PRIORITY_COLOR } from '../constants/maxStatus';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rTasks(): a task list with checkbox toggle + delete. "+ Add Task"
// opens the shared Assign Task modal (reference addTaskGold → addHKPrompt).
export function TasksTab() {
  const { tasks, actions } = useMaxDemo();
  return (
    <Card title="Task Manager" action={<DemoButton sm onClick={() => actions.openModal('addTask')}>+ Add Task</DemoButton>}>
      {tasks.map((t) => (
        <div key={t.id} className={`mb-[7px] flex items-center gap-[11px] rounded-[10px] border border-white/[0.05] bg-[#071120] px-[13px] py-[11px]${t.done ? ' opacity-50' : ''}`}>
          <input type="checkbox" checked={t.done} onChange={(e) => actions.toggleTask(t.id, e.target.checked)} className="h-3.5 w-3.5 flex-shrink-0 accent-[#f59e0b]" />
          <div className="flex-1">
            <div className={`text-[13px] text-[#f4f8ff] ${t.done ? 'line-through' : ''}`}>{t.title}</div>
            <div className="text-[10px] text-[#4b6278]">Due {t.due} • <span style={{ color: TASK_PRIORITY_COLOR[t.priority] || '#4fc87a' }}>{t.priority}</span></div>
          </div>
          <DemoButton variant="r" sm onClick={() => actions.deleteTask(t.id)}>✕</DemoButton>
        </div>
      ))}
    </Card>
  );
}
