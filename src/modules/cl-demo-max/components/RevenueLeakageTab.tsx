import { Card, DemoButton, StatGrid, StatTile, TBL, TD, TH } from '@/shared/cl-demo';
import { LEAK_STATUS_CLS } from '../constants/maxStatus';
import { useMaxDemo } from '../hooks/useMaxDemo';

const BADGE = 'inline-block rounded-full px-2 py-0.5 text-[10px] font-bold';

// Reproduces rRevenue(): leakage KPIs + an itemized leakage table.
export function RevenueLeakageTab() {
  const { leakItems, actions } = useMaxDemo();
  const total = leakItems.reduce((s, i) => s + i.amount, 0);

  return (
    <>
      <StatGrid>
        <StatTile label="Monthly Leakage" value={`$${total.toLocaleString()}`} valueClassName="text-[#f87171]" sub="Identified" subClassName="text-[#f87171]" />
        <StatTile label="Recoverable" value={`$${Math.round(total * 0.72).toLocaleString()}`} valueClassName="text-[#4fc87a]" sub="Estimated" subClassName="text-[#4fc87a]" />
        <StatTile label="Open Issues" value={leakItems.length} />
      </StatGrid>

      <Card title="Revenue Leakage Items" action={<DemoButton sm onClick={() => actions.toast('Scan complete — 3 new items flagged!')}>Run Full Scan</DemoButton>}>
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>{['Issue', 'Type', 'Monthly Impact', 'Status', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {leakItems.map((i, idx) => (
                <tr key={idx} className="hover:bg-white/[0.02]">
                  <td className={`${TD} max-w-[220px] text-[12px]`}>{i.issue}</td>
                  <td className={TD}><span className={`${BADGE} bg-[#f87171]/10 text-[#f87171]`}>{i.type}</span></td>
                  <td className={`${TD} font-bold text-[#f87171]`}>-${i.amount.toLocaleString()}</td>
                  <td className={TD}><span className={`${BADGE} ${LEAK_STATUS_CLS[i.status] || LEAK_STATUS_CLS.pending}`}>{i.status.replace(/_/g, ' ')}</span></td>
                  <td className={TD}><DemoButton variant="x" sm onClick={() => actions.toast('Issue assigned for resolution.')}>Resolve</DemoButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
