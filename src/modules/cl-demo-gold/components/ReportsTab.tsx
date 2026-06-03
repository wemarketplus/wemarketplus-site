import { Badge, Card, DemoButton, StatGrid, StatTile, TBL, TD, TH, useCsvDownload } from '@/shared/cl-demo';
import type { BadgeTone } from '@/shared/cl-demo';
import { REPORT_STATUS_LABEL } from '../constants/goldStatus';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { buildGoldReportCsv } from '../utils/goldCsv';
import {
  activeLeadCount,
  countAptStatus,
  occupancyRate,
  openHkCount,
  openMaintCount,
  openMrCount,
} from '../utils/goldFormat';

// Reproduces rReports(): the KPI strip and an operations-summary table with a
// CSV export.
export function ReportsTab() {
  const { apts, leads, mrTickets, maintTickets, hkTasks, actions } = useGoldDemo();
  const download = useCsvDownload();

  const occ = occupancyRate(apts);
  const active = activeLeadCount(leads);
  const mrOpen = openMrCount(mrTickets);
  const maintOpen = openMaintCount(maintTickets);

  const rows: Array<[string, string, string | number, BadgeTone]> = [
    ['Occupancy', 'Current Rate', `${occ}%`, 'green'],
    ['Sales', 'Active Leads', active, 'amber'],
    ['Operations', 'Make-Ready In Progress', mrOpen, 'amber'],
    ['Operations', 'Open Maintenance', maintOpen, 'red'],
    ['Operations', 'Available Units', countAptStatus(apts, 'available'), 'blue'],
    ['Operations', 'Housekeeping Tasks Due', openHkCount(hkTasks), 'amber'],
  ];

  const exportCsv = () => {
    download(buildGoldReportCsv(apts, leads), 'gold-report');
    actions.toast('Report exported!');
  };

  return (
    <>
      <StatGrid>
        <StatTile label="Occupancy" value={`${occ}%`} valueClassName="text-[#4fc87a]" />
        <StatTile label="Active Leads" value={active} />
        <StatTile label="Open MR Tickets" value={mrOpen} valueClassName="text-[#f59e0b]" />
        <StatTile label="Open Maint." value={maintOpen} valueClassName="text-[#f87171]" />
      </StatGrid>

      <Card
        title="Operations Summary"
        action={<DemoButton sm onClick={exportCsv}>Export CSV</DemoButton>}
      >
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>
                {['Category', 'Metric', 'Value', 'Status'].map((h) => (
                  <th key={h} className={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map(([cat, metric, value, tone], i) => (
                <tr key={i} className="hover:bg-white/[0.02]">
                  <td className={TD}>{cat}</td>
                  <td className={TD}>{metric}</td>
                  <td className={`${TD} font-bold text-[#f4f8ff]`}>{value}</td>
                  <td className={TD}><Badge tone={tone}>{REPORT_STATUS_LABEL[tone]}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
