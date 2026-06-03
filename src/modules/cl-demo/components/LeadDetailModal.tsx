import { useEffect, useState } from 'react';
import { ClDemoModal } from './ClDemoModal';
import { DemoButton, FI, FLB } from '@/shared/cl-demo';
import { LEAD_STATUSES_FULL } from '../constants/clDemoData';
import { useClDemo } from '../hooks/useClDemo';
import type { LeadStatus, Urgency } from '../types/clDemoTypes';

// Lead detail/edit modal — reproduces openLead()/updateLead(). Reads the open
// lead from the slice (leadModalId) and edits status/urgency/follow-up/source/notes.
export function LeadDetailModal() {
  const { leads, leadModalId, actions } = useClDemo();
  const lead = leads.find((l) => l.id === leadModalId) ?? null;

  const [status, setStatus] = useState<LeadStatus>('Inquiry');
  const [urgency, setUrgency] = useState<Urgency>('Warm');
  const [fu, setFu] = useState('');
  const [source, setSource] = useState('');
  const [notes, setNotes] = useState('');

  useEffect(() => {
    if (!lead) return;
    setStatus(lead.status);
    setUrgency(lead.urgency || 'Warm');
    setFu(lead.fu);
    setSource(lead.source);
    setNotes(lead.notes);
  }, [lead]);

  const save = () => {
    if (!lead) return;
    actions.saveLeadEdit({ id: lead.id, status, urgency, fu, source, notes });
    actions.toast('Lead updated: ' + lead.name);
    actions.closeLead();
  };

  return (
    <ClDemoModal open={!!lead} onClose={actions.closeLead}>
      {lead && (
        <>
          <h3 className="mb-1 text-[17px] font-extrabold text-[#f4f8ff]">{lead.name}</h3>
          <div className="mb-4 text-[12px] text-[#6b7fa3]">
            {lead.care} • {lead.phone}
          </div>
          <div className="mb-[14px] grid grid-cols-2 gap-2.5">
            <div>
              <div className={`mb-1 ${FLB}`}>Status</div>
              <select className={FI} value={status} onChange={(e) => setStatus(e.target.value as LeadStatus)}>
                {LEAD_STATUSES_FULL.map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <div className={`mb-1 ${FLB}`}>Urgency</div>
              <select className={FI} value={urgency} onChange={(e) => setUrgency(e.target.value as Urgency)}>
                <option value="Hot">Hot</option>
                <option value="Warm">Warm</option>
                <option value="Cold">Cold</option>
              </select>
            </div>
            <div>
              <div className={`mb-1 ${FLB}`}>Follow-Up Date</div>
              <input className={FI} type="date" value={fu} onChange={(e) => setFu(e.target.value)} />
            </div>
            <div>
              <div className={`mb-1 ${FLB}`}>Source</div>
              <input className={FI} value={source} onChange={(e) => setSource(e.target.value)} />
            </div>
          </div>
          <div className="mb-3">
            <div className={`mb-1 ${FLB}`}>Notes</div>
            <textarea className={`${FI} min-h-[72px] resize-y`} rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
          <div className="flex gap-2">
            <DemoButton onClick={save}>Save Changes</DemoButton>
            <DemoButton variant="x" onClick={actions.closeLead}>Close</DemoButton>
          </div>
        </>
      )}
    </ClDemoModal>
  );
}
