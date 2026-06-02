import { Card } from './Card';
import { DemoButton } from './DemoButton';
import { useClDemo } from '../hooks/useClDemo';

// Dashboard "✅ Tasks Due Today" card — first 4 open tasks with toggle checkboxes.
export function TasksDueCard() {
  const { tasks, actions } = useClDemo();
  const open = tasks.filter((t) => !t.done).slice(0, 4);

  return (
    <Card
      title="✅ Tasks Due Today"
      action={
        <DemoButton variant="x" sm onClick={() => actions.setTab('tasks')}>
          All Tasks
        </DemoButton>
      }
    >
      {open.map((t) => (
        <div key={t.id} className="flex items-center gap-2.5 border-b border-white/[0.04] py-[7px]">
          <input
            type="checkbox"
            onChange={(e) => actions.toggleTask(t.id, e.target.checked)}
            className="flex-shrink-0 accent-[#f59e0b]"
          />
          <div className="flex-1">
            <div className="text-[12px] text-[#c8d6e8]">{t.title}</div>
            <div className="text-[10px] text-[#4b6278]">
              Due {t.due} •{' '}
              <span className={t.priority === 'High' ? 'text-[#f87171]' : 'text-[#f59e0b]'}>
                {t.priority}
              </span>
            </div>
          </div>
        </div>
      ))}
    </Card>
  );
}
