import { Badge, Card, DemoButton, TBL, TD, TH } from '@/shared/cl-demo';
import { useGoldDemo } from '../hooks/useGoldDemo';

// Reproduces rRefs(): the referral-sources table with a "Log Visit" action.
export function ReferralsTab() {
  const { referrals, actions } = useGoldDemo();

  return (
    <Card
      title="Referral Sources"
      action={<DemoButton sm onClick={actions.promptAddRef}>+ Add Source</DemoButton>}
    >
      <div className="overflow-x-auto">
        <table className={TBL}>
          <thead>
            <tr>
              {['Name', 'Type', 'Org', 'Leads Sent', 'Last Contact', 'Actions'].map((h) => (
                <th key={h} className={TH}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {referrals.map((r) => (
              <tr key={r.id} className="hover:bg-white/[0.02]">
                <td className={`${TD} font-bold text-[#f4f8ff]`}>{r.name}</td>
                <td className={TD}><Badge tone="blue">{r.type}</Badge></td>
                <td className={TD}>{r.org}</td>
                <td className={`${TD} font-bold text-[#4fc87a]`}>{r.leads}</td>
                <td className={TD}>{r.last}</td>
                <td className={TD}>
                  <DemoButton sm onClick={() => actions.logRefVisit(r.id)}>Log Visit</DemoButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
