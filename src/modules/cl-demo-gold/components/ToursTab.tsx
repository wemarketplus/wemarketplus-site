import { useState } from 'react';
import { Badge, Card, DemoButton, Field, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { TOURS } from '../constants/goldData';
import { useGoldDemo } from '../hooks/useGoldDemo';

// Reproduces rTours(): the upcoming-tours table plus an inline "Schedule Tour"
// form (saving just toasts, matching the reference's saveTourGold()).
export function ToursTab() {
  const { tourFormOpen, actions } = useGoldDemo();
  const [name, setName] = useState('');
  const [date, setDate] = useState('');
  const [time, setTime] = useState('10:00');
  const [guide, setGuide] = useState('');

  return (
    <Card
      title="Upcoming Tours"
      action={<DemoButton sm onClick={() => actions.setTourForm(true)}>+ Schedule Tour</DemoButton>}
    >
      {tourFormOpen && (
        <div className="mb-[14px] rounded-[10px] border border-[#f59e0b]/15 bg-[#071120] p-[14px]">
          <div className="mb-3 grid grid-cols-2 gap-3">
            <Field label="Prospect *">
              <input autoComplete="off" className={FI} placeholder="Prospect name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Date *">
              <input autoComplete="off" className={FI} type="date" value={date} onChange={(e) => setDate(e.target.value)} />
            </Field>
            <Field label="Time">
              <input autoComplete="off" className={FI} type="time" value={time} onChange={(e) => setTime(e.target.value)} />
            </Field>
            <Field label="Guide">
              <input autoComplete="off" className={FI} placeholder="Sarah M." value={guide} onChange={(e) => setGuide(e.target.value)} />
            </Field>
          </div>
          <div className="flex gap-2">
            <DemoButton sm onClick={() => actions.saveTour(name.trim(), date)}>Schedule</DemoButton>
            <DemoButton variant="x" sm onClick={() => actions.setTourForm(false)}>Cancel</DemoButton>
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className={TBL}>
          <thead>
            <tr>
              {['Prospect', 'Care', 'Date', 'Time', 'Guide', 'Status', 'Actions'].map((h) => (
                <th key={h} className={TH}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TOURS.map((t) => (
              <tr key={t.name} className="hover:bg-white/[0.02]">
                <td className={`${TD} font-bold`}>{t.name}</td>
                <td className={TD}>{t.care}</td>
                <td className={TD}>{t.date}</td>
                <td className={TD}>{t.time}</td>
                <td className={TD}>{t.guide}</td>
                <td className={TD}><Badge tone={t.status === 'Confirmed' ? 'green' : 'amber'}>{t.status}</Badge></td>
                <td className={TD}>
                  <DemoButton variant="x" sm onClick={() => actions.toast('Tour rescheduled!')}>Edit</DemoButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
