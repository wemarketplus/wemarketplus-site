import { useState } from 'react';
import { Badge, cap, Card, DemoButton, Field, FI, StatGrid, StatTile, TBL, TD, TH } from '@/shared/cl-demo';
import { CONCESSION_TYPE_OPTS } from '../constants/maxForms';
import { CONCESSION_STATUS_TONE, CONCESSION_VALUE_COLOR } from '../constants/maxStatus';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rConcessions(): KPIs + an approval queue with an inline add form.
export function ConcessionsTab() {
  const { concessions, actions } = useMaxDemo();
  const [open, setOpen] = useState(false);
  const [res, setRes] = useState('');
  const [type, setType] = useState(CONCESSION_TYPE_OPTS[0]);
  const [val, setVal] = useState('');
  const [unit, setUnit] = useState('');

  const pending = concessions.filter((c) => c.status === 'pending');
  const pendVal = pending.reduce((s, c) => s + c.value, 0);
  const approved = concessions.filter((c) => c.status === 'approved');

  const submit = () => {
    if (!res.trim()) { actions.toast('Resident name required.', true); return; }
    actions.addConcession({ unit: unit.trim() || 'TBD', resident: res.trim(), type, value: parseInt(val) || 0 });
    setOpen(false); setRes(''); setVal(''); setUnit('');
  };

  return (
    <>
      <StatGrid>
        <StatTile label="Pending" value={pending.length} valueClassName="text-[#f59e0b]" sub="Await decision" subClassName="text-[#f59e0b]" />
        <StatTile label="Pending Value" value={`$${pendVal.toLocaleString()}`} valueClassName="text-[#f87171]" />
        <StatTile label="Approved (Mo)" value={approved.length} valueClassName="text-[#4fc87a]" />
      </StatGrid>

      <Card title="Concession Queue" action={<DemoButton sm onClick={() => setOpen(true)}>+ New Request</DemoButton>}>
        {open && (
          <div className="mb-[14px] rounded-[10px] border border-[#f59e0b]/15 bg-[#071120] p-[14px]">
            <div className="mb-3 grid grid-cols-2 gap-3">
              <Field label="Resident Name"><input className={FI} placeholder="Dorothy Harrison" value={res} onChange={(e) => setRes(e.target.value)} /></Field>
              <Field label="Concession Type"><select className={FI} value={type} onChange={(e) => setType(e.target.value)}>{CONCESSION_TYPE_OPTS.map((t) => <option key={t}>{t}</option>)}</select></Field>
              <Field label="Value ($)"><input className={FI} type="number" placeholder="2500" value={val} onChange={(e) => setVal(e.target.value)} /></Field>
              <Field label="Unit"><input className={FI} placeholder="102" value={unit} onChange={(e) => setUnit(e.target.value)} /></Field>
            </div>
            <div className="flex gap-2"><DemoButton sm onClick={submit}>Submit Request</DemoButton><DemoButton variant="x" sm onClick={() => setOpen(false)}>Cancel</DemoButton></div>
          </div>
        )}
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>{['ID', 'Unit', 'Resident', 'Type', 'Value', 'Status', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {concessions.map((c) => (
                <tr key={c.id} className="hover:bg-white/[0.02]">
                  <td className={`${TD} font-bold text-[#f59e0b]`}>{c.id}</td>
                  <td className={TD}>{c.unit}</td>
                  <td className={`${TD} font-bold`}>{c.resident}</td>
                  <td className={TD}>{c.type}</td>
                  <td className={TD} style={{ color: CONCESSION_VALUE_COLOR[c.status] }}>${c.value.toLocaleString()}</td>
                  <td className={TD}><Badge tone={CONCESSION_STATUS_TONE[c.status]}>{cap(c.status)}</Badge></td>
                  <td className={TD}>
                    {c.status === 'pending' ? (
                      <div className="flex gap-1"><DemoButton variant="g" sm onClick={() => actions.decideConcession(c.id, 'approved')}>Approve</DemoButton><DemoButton variant="r" sm onClick={() => actions.decideConcession(c.id, 'denied')}>Deny</DemoButton></div>
                    ) : (
                      <DemoButton variant="x" sm>View</DemoButton>
                    )}
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
