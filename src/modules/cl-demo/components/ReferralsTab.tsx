import { Card } from '@/shared/cl-demo';
import { Badge } from '@/shared/cl-demo';
import { DemoButton } from '@/shared/cl-demo';
import { TBL, TD, TH } from '@/shared/cl-demo';
import { useClDemo } from '../hooks/useClDemo';

// Referral Sources tab — reproduces rRefs(): partner table, Log Visit (bumps
// count + adds outreach), admin-only delete, + Add Source.
export function ReferralsTab() {
  const { referrals, role, actions } = useClDemo();

  return (
    <Card
      title="Referral Partners"
      action={
        <DemoButton sm onClick={() => actions.setTab('addref')}>
          + Add Source
        </DemoButton>
      }
    >
      <table className={TBL}>
        <thead>
          <tr>
            {['Name', 'Type', 'Organization', 'Leads Sent', 'Last Contact', 'Actions'].map((h) => (
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
              <td className={`${TD} text-[11px]`}>{r.last}</td>
              <td className={TD}>
                <div className="flex gap-1.5">
                  <DemoButton
                    sm
                    onClick={() => {
                      actions.logRefVisit(r.id);
                      actions.toast('Visit logged for ' + r.name);
                    }}
                  >
                    Log Visit
                  </DemoButton>
                  {role === 'admin' && (
                    <DemoButton
                      variant="r"
                      sm
                      onClick={() => {
                        if (window.confirm('Remove this referral source?')) {
                          actions.deleteRef(r.id);
                          actions.toast('Referral source removed.');
                        }
                      }}
                    >
                      ✕
                    </DemoButton>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
