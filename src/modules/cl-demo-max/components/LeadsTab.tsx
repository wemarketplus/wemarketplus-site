import { useState } from 'react';
import { Badge, Card, DemoButton, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { LEAD_FILTER_STATUSES } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { leadStatusTone, urgencyTone } from '../utils/maxFormat';

// Reproduces rLeads(): search + status filter, leads table, status "Update",
// and an "+ Add Lead" modal trigger.
export function LeadsTab() {
  const { leads, actions } = useMaxDemo();
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');

  const filtered = leads.filter(
    (l) =>
      (!q || l.name.toLowerCase().includes(q.toLowerCase()) || l.care.toLowerCase().includes(q.toLowerCase())) &&
      (!status || l.status === status),
  );

  return (
    <Card
      title={
        <div className="flex flex-wrap items-center gap-2">
          <input className={`${FI} w-[180px]`} placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
          <select className={`${FI} w-[150px]`} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All Status</option>
            {LEAD_FILTER_STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
      }
      action={<DemoButton sm onClick={() => actions.openModal('addLead')}>+ Add Lead</DemoButton>}
    >
      <div className="overflow-x-auto">
        <table className={TBL}>
          <thead>
            <tr>{['Name', 'Care', 'Status', 'Urgency', 'Source', 'Follow-Up', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="px-2.5 py-5 text-center text-[#4b6278]">No leads found.</td></tr>
            ) : (
              filtered.map((l) => (
                <tr key={l.id} className="hover:bg-white/[0.02]">
                  <td className={`${TD} font-bold text-[#f4f8ff]`}>{l.name}</td>
                  <td className={TD}>{l.care}</td>
                  <td className={TD}><Badge tone={leadStatusTone(l.status)}>{l.status}</Badge></td>
                  <td className={TD}><Badge tone={urgencyTone(l.urgency)}>{l.urgency || '—'}</Badge></td>
                  <td className={`${TD} text-[11px]`}>{l.source}</td>
                  <td className={`${TD} text-[11px]`}>{l.fu || '—'}</td>
                  <td className={TD}><DemoButton sm onClick={() => actions.cycleLeadStatus(l.id)}>Update</DemoButton></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
