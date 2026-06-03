import { Badge, cap, DemoButton, TBL, TD, TH } from '@/shared/cl-demo';
import { HK_STATUS_TONE } from '../constants/maxStatus';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rHKCore(): the housekeeping task table, shared by the housekeeping
// dashboard and the Housekeeping Tasks tab.
export function HousekeepingTable() {
  const { hkTasks, actions } = useMaxDemo();
  return (
    <div className="overflow-x-auto">
      <table className={TBL}>
        <thead>
          <tr>{['Task', 'Unit/Area', 'Type', 'Status', 'Assigned', 'Due', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {hkTasks.map((t) => (
            <tr key={t.id} className="hover:bg-white/[0.02]">
              <td className={TD}>{t.task}</td>
              <td className={TD}>{t.unit}</td>
              <td className={TD}>{t.type}</td>
              <td className={TD}><Badge tone={HK_STATUS_TONE[t.status] || 'neutral'}>{cap(t.status.replace(/_/g, ' '))}</Badge></td>
              <td className={TD}>{t.assignee}</td>
              <td className={TD}>{t.due}</td>
              <td className={TD}><DemoButton variant="x" sm onClick={() => actions.cycleHkStatus(t.id)}>{t.status === 'completed' ? 'Reopen' : 'Update'}</DemoButton></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
