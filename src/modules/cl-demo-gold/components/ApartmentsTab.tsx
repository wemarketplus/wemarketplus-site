import { Badge, Card, DemoButton, StatGrid, StatTile, TBL, TD, TH } from '@/shared/cl-demo';
import { APT_STATUS_LABELS, APT_STATUS_TONE } from '../constants/goldStatus';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { countAptStatus, occupancyRate } from '../utils/goldFormat';

// Reproduces rApartments(): a five-stat strip and the full unit inventory table
// with status-aware row actions.
export function ApartmentsTab() {
  const { apts, actions } = useGoldDemo();

  return (
    <>
      <StatGrid>
        <StatTile label="Occupied" value={countAptStatus(apts, 'occupied')} valueClassName="text-[#4fc87a]" />
        <StatTile label="Available" value={countAptStatus(apts, 'available')} valueClassName="text-[#3d9ee8]" />
        <StatTile label="Make-Ready" value={countAptStatus(apts, 'make_ready')} valueClassName="text-[#f59e0b]" />
        <StatTile label="On-Notice" value={countAptStatus(apts, 'on_notice')} valueClassName="text-[#f87171]" />
        <StatTile label="Occupancy" value={`${occupancyRate(apts)}%`} />
      </StatGrid>

      <Card
        title={`All Units (${apts.length})`}
        action={<DemoButton sm onClick={actions.promptAddApt}>+ Add Unit</DemoButton>}
      >
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>
                {['Unit', 'Type', 'Care', 'Status', 'Resident', 'Rate/Mo', 'MR Tasks', 'Actions'].map((h) => (
                  <th key={h} className={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {apts.map((a) => (
                <tr key={a.id} className="hover:bg-white/[0.02]">
                  <td className={`${TD} font-extrabold text-[#f4f8ff]`}>{a.unit}</td>
                  <td className={TD}>{a.type}</td>
                  <td className={TD}><Badge tone="blue">{a.care}</Badge></td>
                  <td className={TD}><Badge tone={APT_STATUS_TONE[a.status]}>{APT_STATUS_LABELS[a.status]}</Badge></td>
                  <td className={TD}>{a.resident || <span className="text-[#4b6278]">Vacant</span>}</td>
                  <td className={TD}>{a.rate ? `$${a.rate.toLocaleString()}` : '—'}</td>
                  <td className={TD}>
                    {a.mrTasks > 0 ? (
                      <span className="text-[#f87171]">{a.mrTasks} open</span>
                    ) : (
                      <span className="text-[#4fc87a]">Clear</span>
                    )}
                  </td>
                  <td className={TD}>
                    <div className="flex gap-[5px]">
                      {a.status === 'on_notice' && (
                        <DemoButton sm onClick={() => actions.scheduleMakeReady(a.id)}>Sched MR</DemoButton>
                      )}
                      {a.status === 'available' && (
                        <DemoButton variant="g" sm onClick={() => actions.setTab('leads')}>Assign Lead</DemoButton>
                      )}
                      <DemoButton variant="x" sm onClick={() => actions.cycleAptStatus(a.id)}>Edit Status</DemoButton>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
