import { Card, StatGrid, StatTile } from '@/shared/cl-demo';
import { LEDGER_CHART_MAX } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rLedger(): KPI strip + a 6-month revenue-vs-budget bar chart.
export function LedgerTab() {
  const { revenueMonths } = useMaxDemo();
  const totalBud = revenueMonths.reduce((s, m) => s + m.bud, 0);
  const totalAct = revenueMonths.reduce((s, m) => s + m.act, 0);
  const variance = totalAct - totalBud;

  return (
    <>
      <StatGrid>
        <StatTile label="YTD Revenue" value={`$${Math.round(totalAct / 1000)}K`} valueClassName="text-[#4fc87a]" sub={`${variance >= 0 ? '↑' : '↓'} $${Math.abs(Math.round(variance / 1000))}K vs budget`} subClassName={variance >= 0 ? 'text-[#4fc87a]' : 'text-[#f87171]'} />
        <StatTile label="Feb Budget" value="$186K" sub="Monthly target" />
        <StatTile label="Feb Actual" value="$161K" valueClassName="text-[#f87171]" sub="↓ $25K below" subClassName="text-[#f87171]" />
        <StatTile label="Avg Rev/Unit" value="$4,280" sub="Occupied units" />
      </StatGrid>

      <Card title="6-Month Revenue vs Budget">
        <div className="flex h-[150px] items-end gap-1.5 px-1">
          {revenueMonths.map((m) => {
            const bH = Math.round((m.bud / LEDGER_CHART_MAX) * 140);
            const aH = Math.round((m.act / LEDGER_CHART_MAX) * 140);
            const color = m.act >= m.bud ? '#4fc87a' : '#f87171';
            return (
              <div key={m.mo} className="flex flex-1 flex-col items-center gap-[3px]">
                <div className="flex h-[140px] items-end gap-0.5">
                  <div className="w-[14px] rounded-t-[3px] bg-[#3d9ee8]/30" style={{ height: bH }} title={`Budget $${Math.round(m.bud / 1000)}K`} />
                  <div className="w-[14px] rounded-t-[3px]" style={{ height: aH, background: color }} title={`Actual $${Math.round(m.act / 1000)}K`} />
                </div>
                <div className="text-[9px] text-[#4b6278]">{m.mo}</div>
              </div>
            );
          })}
        </div>
        <div className="mt-2.5 flex gap-4">
          <div className="flex items-center gap-1.5"><div className="h-2.5 w-2.5 rounded-[2px] bg-[#3d9ee8]/40" /><span className="text-[11px] text-[#4b6278]">Budget</span></div>
          <div className="flex items-center gap-1.5"><div className="h-2.5 w-2.5 rounded-[2px] bg-[#4fc87a]" /><span className="text-[11px] text-[#4b6278]">Actual (on/over)</span></div>
          <div className="flex items-center gap-1.5"><div className="h-2.5 w-2.5 rounded-[2px] bg-[#f87171]" /><span className="text-[11px] text-[#4b6278]">Actual (under)</span></div>
        </div>
      </Card>
    </>
  );
}
