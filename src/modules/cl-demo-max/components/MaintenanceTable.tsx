import { Badge, cap, DemoButton, TBL, TD, TH } from '@/shared/cl-demo';
import { MAINT_PRIORITY_TONE, MAINT_STATUS_TONE } from '../constants/maxStatus';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rMaintCore(): the work-orders table, shared by the maintenance
// dashboard and the Maintenance Tickets tab.
export function MaintenanceTable() {
  const { maintTickets, actions } = useMaxDemo();
  return (
    <div className="overflow-x-auto">
      <table className={TBL}>
        <thead>
          <tr>{['Ticket', 'Unit', 'Issue', 'Priority', 'Status', 'Assigned', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {maintTickets.map((t) => (
            <tr key={t.id} className="hover:bg-white/[0.02]">
              <td className={`${TD} font-bold text-[#f59e0b]`}>{t.ticket}</td>
              <td className={TD}>{t.unit}</td>
              <td className={`${TD} max-w-[160px]`}>{t.issue}</td>
              <td className={TD}><Badge tone={MAINT_PRIORITY_TONE[t.priority] || 'neutral'}>{t.priority}</Badge></td>
              <td className={TD}><Badge tone={MAINT_STATUS_TONE[t.status] || 'neutral'}>{cap(t.status.replace(/_/g, ' '))}</Badge></td>
              <td className={TD}>{t.assignee}</td>
              <td className={TD}><DemoButton variant="x" sm onClick={() => actions.cycleMaintStatus(t.id)}>{t.status === 'completed' ? 'Reopen' : 'Update'}</DemoButton></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
