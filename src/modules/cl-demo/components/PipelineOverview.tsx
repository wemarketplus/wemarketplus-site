import { Card } from '@/shared/cl-demo';
import { STAGE_COLORS, STAGES } from '../constants/clDemoNav';
import { useClDemo } from '../hooks/useClDemo';
import { stageCounts } from '../utils/clDemoFormat';

// Dashboard "📊 Pipeline Overview" — a strip of stage boxes with colored counts.
export function PipelineOverview() {
  const { leads, actions } = useClDemo();
  const counts = stageCounts(leads);

  return (
    <Card title="📊 Pipeline Overview">
      <div className="flex flex-wrap gap-2.5">
        {STAGES.map((stage) => (
          <div
            key={stage}
            onClick={() => actions.setTab('leads')}
            role="button"
            className="min-w-[90px] cursor-pointer rounded-[10px] border border-white/[0.07] bg-[#060e1b] px-4 py-3 text-center"
          >
            <div className="text-[22px] font-black" style={{ color: STAGE_COLORS[stage] }}>
              {counts[stage]}
            </div>
            <div className="mt-0.5 text-[10px] text-[#6b7fa3]">{stage}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}
