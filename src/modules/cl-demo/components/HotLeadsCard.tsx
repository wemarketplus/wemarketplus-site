import { Card } from './Card';
import { DemoButton } from './DemoButton';
import { useClDemo } from '../hooks/useClDemo';
import { hotLeads } from '../utils/clDemoFormat';

// Dashboard "🔥 Hot Leads" card — lists Hot-urgency leads with a View action.
export function HotLeadsCard() {
  const { leads, actions } = useClDemo();
  const hot = hotLeads(leads);

  return (
    <Card
      title="🔥 Hot Leads"
      action={
        <DemoButton sm onClick={() => actions.setTab('leads')}>
          View All
        </DemoButton>
      }
    >
      {hot.map((l) => (
        <div
          key={l.id}
          className="flex items-center justify-between border-b border-white/[0.04] py-2"
        >
          <div>
            <div className="text-[13px] font-bold text-[#f4f8ff]">{l.name}</div>
            <div className="text-[10px] text-[#4b6278]">
              {l.care} • {l.status}
            </div>
          </div>
          <DemoButton sm onClick={() => actions.openLead(l.id)}>
            View
          </DemoButton>
        </div>
      ))}
    </Card>
  );
}
