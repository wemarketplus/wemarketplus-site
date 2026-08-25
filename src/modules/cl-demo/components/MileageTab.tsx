import { useState } from 'react';
import {
  Card,
  DemoButton,
  Field,
  StatGrid,
  StatTile,
  FG,
  FI,
  TBL,
  TD,
  TH,
  useCsvDownload,
} from '@/shared/cl-demo';
import { IRS_RATE } from '../constants/clDemoNav';
import { useClDemo } from '../hooks/useClDemo';
import { reimbursable, totalMiles } from '../utils/clDemoFormat';
import { buildMileageCsv } from '../utils/clDemoCsv';

// Mileage Tracker tab — reproduces rMileage(): totals, a log-trip form, the
// mileage table with per-row delete, and Export CSV.
export function MileageTab() {
  const { mileage, actions } = useClDemo();
  const download = useCsvDownload();
  const [date, setDate] = useState('');
  const [miles, setMiles] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [purpose, setPurpose] = useState('');

  const total = totalMiles(mileage);

  const save = () => {
    const m = parseFloat(miles);
    if (!m || !date) {
      actions.toast('Miles and date required.', true);
      return;
    }
    actions.addMileage({ date, miles: m, from: from || 'Sunrise SL', to, purpose: purpose || 'Visit' });
    actions.toast(`${m} miles logged — $${reimbursable(m)} reimbursable!`);
    setDate('');
    setMiles('');
    setFrom('');
    setTo('');
    setPurpose('');
  };

  return (
    <>
      <StatGrid>
        <StatTile label="Feb Total Miles" value={total} sub={`$${reimbursable(total)} reimbursable`} subClassName="text-[#4fc87a]" />
        <StatTile label="Trips Logged" value={mileage.length} />
        <StatTile label="IRS Rate" value={<span className="text-[20px]">${IRS_RATE.toFixed(2)}</span>} sub="Per mile 2026" />
      </StatGrid>

      <Card title="Log New Trip">
        <div className={FG}>
          <Field label="Date *">
            <input autoComplete="off" className={FI} type="date" value={date} onChange={(e) => setDate(e.target.value)} />
          </Field>
          <Field label="Miles *">
            <input autoComplete="off" className={FI} type="number" step="0.1" value={miles} onChange={(e) => setMiles(e.target.value)} placeholder="12.4" />
          </Field>
          <Field label="From">
            <input autoComplete="off" className={FI} value={from} onChange={(e) => setFrom(e.target.value)} placeholder="Sunrise Senior Living" />
          </Field>
          <Field label="To">
            <input autoComplete="off" className={FI} value={to} onChange={(e) => setTo(e.target.value)} placeholder="Parkland Hospital" />
          </Field>
          <Field label="Purpose" wide>
            <input autoComplete="off" className={FI} value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="Referral visit, community event…" />
          </Field>
        </div>
        <DemoButton onClick={save}>Log Trip</DemoButton>
      </Card>

      <Card
        title="Mileage Log"
        action={
          <DemoButton variant="x" sm onClick={() => { download(buildMileageCsv(mileage), 'mileage'); actions.toast('Mileage CSV exported!'); }}>
            Export CSV
          </DemoButton>
        }
      >
        <table className={TBL}>
          <thead>
            <tr>
              {['Date', 'From', 'To', 'Miles', 'Purpose', 'Reimbursable', ''].map((h, i) => (
                <th key={i} className={TH}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {mileage.map((m) => (
              <tr key={m.id} className="hover:bg-white/[0.02]">
                <td className={TD}>{m.date}</td>
                <td className={`${TD} text-[11px]`}>{m.from}</td>
                <td className={`${TD} text-[11px]`}>{m.to}</td>
                <td className={`${TD} font-bold text-[#f4f8ff]`}>{m.miles}</td>
                <td className={`${TD} text-[11px]`}>{m.purpose}</td>
                <td className={`${TD} text-[#4fc87a]`}>${reimbursable(m.miles)}</td>
                <td className={TD}>
                  <DemoButton variant="r" sm onClick={() => { actions.deleteMileage(m.id); actions.toast('Entry removed.'); }}>✕</DemoButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
