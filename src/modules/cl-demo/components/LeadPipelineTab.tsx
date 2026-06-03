import { useState } from 'react';
import { Badge, Card, DemoButton, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { LEAD_STATUSES_FULL, URGENCIES } from '../constants/clDemoData';
import { useClDemo } from '../hooks/useClDemo';
import { filterLeads, statusBadgeTone, urgencyBadgeTone } from '../utils/clDemoFormat';

// Lead Pipeline tab — reproduces rLeads(): search + stage + urgency filters,
// a leads table, View (modal) per row, and admin-only delete.
export function LeadPipelineTab() {
  const { leads, role, actions } = useClDemo();
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const [urg, setUrg] = useState('');

  const filtered = filterLeads(leads, q, status, urg);

  return (
    <Card
      title={
        <div className="flex flex-wrap items-center gap-2">
          <input className={`${FI} w-[200px]`} placeholder="Search leads…" value={q} onChange={(e) => setQ(e.target.value)} />
          <select className={`${FI} w-[160px]`} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All Stages</option>
            {LEAD_STATUSES_FULL.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className={`${FI} w-[120px]`} value={urg} onChange={(e) => setUrg(e.target.value)}>
            <option value="">All Urgency</option>
            {URGENCIES.map((u) => <option key={u} value={u}>{u}</option>)}
          </select>
        </div>
      }
      action={
        <DemoButton sm onClick={() => actions.setTab('addlead')}>
          + Add Lead
        </DemoButton>
      }
    >
      <div className="overflow-x-auto">
        <table className={TBL}>
          <thead>
            <tr>
              {['Name', 'Care Level', 'Status', 'Urgency', 'Source', 'Follow-Up', 'Actions'].map((h) => (
                <th key={h} className={TH}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-2.5 py-5 text-center text-[#4b6278]">No leads found.</td>
              </tr>
            ) : (
              filtered.map((l) => (
                <tr key={l.id} className="hover:bg-white/[0.02]">
                  <td className={TD}>
                    <div className="font-bold text-[#f4f8ff]">{l.name}</div>
                    <div className="text-[10px] text-[#4b6278]">{l.phone}</div>
                  </td>
                  <td className={TD}>{l.care}</td>
                  <td className={TD}><Badge tone={statusBadgeTone(l.status)}>{l.status}</Badge></td>
                  <td className={TD}><Badge tone={urgencyBadgeTone(l.urgency)}>{l.urgency || '—'}</Badge></td>
                  <td className={`${TD} text-[11px]`}>{l.source}</td>
                  <td className={`${TD} text-[11px]`}>{l.fu || '—'}</td>
                  <td className={TD}>
                    <div className="flex gap-1.5">
                      <DemoButton sm onClick={() => actions.openLead(l.id)}>View</DemoButton>
                      {role === 'admin' && (
                        <DemoButton
                          variant="r"
                          sm
                          onClick={() => {
                            if (window.confirm('Delete this lead?')) {
                              actions.deleteLead(l.id);
                              actions.toast('Lead removed.');
                            }
                          }}
                        >
                          ✕
                        </DemoButton>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
