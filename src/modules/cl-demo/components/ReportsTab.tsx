import { Card } from './Card';
import { DemoButton } from './DemoButton';
import { StatGrid } from './StatGrid';
import { StatTile } from './StatTile';
import { SOURCE_CHART_COLORS } from '../constants/clDemoNav';
import { TBL, TD, TH } from '../constants/clDemoStyles';
import { useClDemo } from '../hooks/useClDemo';
import { useCsvDownload } from '../hooks/useCsvDownload';
import { activeLeadCount, bySourceChart, moveInCount, pipelineSnapshot } from '../utils/clDemoFormat';
import { buildLeadsReportCsv } from '../utils/clDemoCsv';

// Reports Center tab — reproduces rReports(): summary stats, leads-by-source
// bar chart, pipeline snapshot table, and Export CSV.
export function ReportsTab() {
  const { leads, tours, actions } = useClDemo();
  const download = useCsvDownload();

  const active = activeLeadCount(leads);
  const moveins = moveInCount(leads);
  const conv = tours.length ? Math.round((moveins / tours.length) * 100) : 0;
  const sources = bySourceChart(leads);
  const snapshot = pipelineSnapshot(leads);

  return (
    <>
      <StatGrid>
        <StatTile label="Active Leads" value={active} />
        <StatTile label="Tours" value={tours.length} />
        <StatTile label="Move-Ins" value={moveins} valueClassName="text-[#4fc87a]" />
        <StatTile label="Tour→Move-In" value={`${conv}%`} sub="Industry avg: 30%" />
      </StatGrid>

      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <Card title="Leads by Source">
          {sources.map((row, i) => (
            <div key={row.source} className="mb-[9px] flex items-center gap-2.5">
              <div className="flex-1 text-[12px] text-[#c8d6e8]">{row.source}</div>
              <div className="h-[5px] w-[90px] overflow-hidden rounded-[3px] bg-[#071120]">
                <div className="h-full" style={{ background: SOURCE_CHART_COLORS[i], width: `${row.pct}%` }} />
              </div>
              <div className="w-[18px] text-right text-[12px] font-bold" style={{ color: SOURCE_CHART_COLORS[i] }}>
                {row.count}
              </div>
            </div>
          ))}
        </Card>

        <Card
          title="Pipeline Snapshot"
          action={
            <DemoButton sm onClick={() => { download(buildLeadsReportCsv(leads), 'leads-report'); actions.toast('Report exported!'); }}>
              Export CSV
            </DemoButton>
          }
        >
          <table className={TBL}>
            <thead>
              <tr>
                {['Stage', 'Count', '%'].map((h) => <th key={h} className={TH}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {snapshot.map((row) => (
                <tr key={row.stage} className="hover:bg-white/[0.02]">
                  <td className={TD}>{row.stage}</td>
                  <td className={`${TD} font-bold text-[#f4f8ff]`}>{row.count}</td>
                  <td className={`${TD} text-[#6b7fa3]`}>{row.pct}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}
