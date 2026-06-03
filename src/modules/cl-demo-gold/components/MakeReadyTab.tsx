import { Badge, Card, DemoButton, PBAR, PBAR_FILL } from '@/shared/cl-demo';
import { cn } from '@/shared/utils/cn';
import { MR_CHIP_BASE } from '../constants/goldStyles';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { mrLabel, mrTaskDone, mrTaskLabel, mrTone } from '../utils/goldFormat';

// Reproduces rMakeReady(): a board of make-ready tickets, each with a progress
// bar, toggleable task chips, and advance / complete actions.
export function MakeReadyTab() {
  const { mrTickets, actions } = useGoldDemo();

  return (
    <Card
      title="Make-Ready Board"
      action={<DemoButton sm onClick={actions.promptAddMr}>+ New Ticket</DemoButton>}
    >
      {mrTickets.map((t) => (
        <div key={t.id} className="mb-2.5 rounded-[12px] border border-white/[0.05] bg-[#071120] p-[14px]">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-[14px] font-extrabold text-[#f4f8ff]">Unit {t.unit} — {t.type}</div>
              <div className="mt-0.5 text-[11px] text-[#4b6278]">
                Move-out: {t.moveout} • Target: {t.target} • Assigned: {t.assignee}
              </div>
            </div>
            <div className="text-right">
              <div className="text-[22px] font-black text-[#f59e0b]">{t.pct}%</div>
              <Badge tone={mrTone(t.pct)}>{mrLabel(t.pct)}</Badge>
            </div>
          </div>

          <div className={PBAR}>
            <div className={PBAR_FILL} style={{ width: `${t.pct}%` }} />
          </div>

          <div className="my-2 flex flex-wrap gap-1.5">
            {t.tasks.map((task, i) => {
              const done = mrTaskDone(task);
              return (
                <button
                  key={i}
                  type="button"
                  onClick={() => actions.toggleMrTask(t.id, i)}
                  className={cn(MR_CHIP_BASE, done ? 'bg-[#4fc87a]/10 text-[#4fc87a]' : 'bg-white/[0.07] text-[#8ba4c4]')}
                >
                  {done ? '✓ ' : '● '}{mrTaskLabel(task)}
                </button>
              );
            })}
          </div>

          <div className="flex gap-2">
            <DemoButton sm onClick={() => actions.advanceMr(t.id)}>Mark 25% Progress</DemoButton>
            <DemoButton variant="g" sm onClick={() => actions.completeMr(t.id)}>Mark Complete</DemoButton>
          </div>
        </div>
      ))}
    </Card>
  );
}
