import { useState } from 'react';
import { Card } from '@/shared/cl-demo';
import { Badge } from '@/shared/cl-demo';
import { DemoButton } from '@/shared/cl-demo';
import { Field } from '@/shared/cl-demo';
import { TOUR_CARE_LEVELS, TOUR_TYPES } from '../constants/clDemoData';
import { FG, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { useClDemo } from '../hooks/useClDemo';

// Tour Scheduler tab — reproduces rTours(): upcoming tours table, an inline
// schedule form, and Confirm/Reschedule toggling.
export function ToursTab() {
  const { tours, tourFormOpen, actions } = useClDemo();
  const [name, setName] = useState('');
  const [care, setCare] = useState<string>(TOUR_CARE_LEVELS[0]);
  const [date, setDate] = useState('');
  const [time, setTime] = useState('10:00');
  const [guide, setGuide] = useState('');

  const save = () => {
    if (!name.trim() || !date) {
      actions.toast('Name and date required.', true);
      return;
    }
    actions.addTour({ name: name.trim(), care, date, time, guide: guide || 'TBD' });
    actions.toast('Tour scheduled for ' + name.trim());
    setName('');
    setDate('');
    setGuide('');
  };

  return (
    <Card
      title="Upcoming Tours"
      action={
        <DemoButton sm onClick={() => actions.setTourForm(true)}>
          + Schedule Tour
        </DemoButton>
      }
    >
      {tourFormOpen && (
        <div className="mb-[14px] rounded-[10px] border border-[#f59e0b]/15 bg-[#071120] p-[14px]">
          <div className={FG}>
            <Field label="Prospect Name *">
              <input className={FI} value={name} onChange={(e) => setName(e.target.value)} placeholder="Dorothy Harrison" />
            </Field>
            <Field label="Care Level">
              <select className={FI} value={care} onChange={(e) => setCare(e.target.value)}>
                {TOUR_CARE_LEVELS.map((c) => <option key={c}>{c}</option>)}
              </select>
            </Field>
            <Field label="Date *">
              <input className={FI} type="date" value={date} onChange={(e) => setDate(e.target.value)} />
            </Field>
            <Field label="Time">
              <input className={FI} type="time" value={time} onChange={(e) => setTime(e.target.value)} />
            </Field>
            <Field label="Tour Guide">
              <input className={FI} value={guide} onChange={(e) => setGuide(e.target.value)} placeholder="Sarah M." />
            </Field>
            <Field label="Type">
              <select className={FI}>
                {TOUR_TYPES.map((t) => <option key={t}>{t}</option>)}
              </select>
            </Field>
          </div>
          <div className="flex gap-2">
            <DemoButton sm onClick={save}>Schedule</DemoButton>
            <DemoButton variant="x" sm onClick={() => actions.setTourForm(false)}>Cancel</DemoButton>
          </div>
        </div>
      )}
      <table className={TBL}>
        <thead>
          <tr>
            {['Prospect', 'Care', 'Date', 'Time', 'Guide', 'Status', 'Actions'].map((h) => (
              <th key={h} className={TH}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {tours.map((t) => (
            <tr key={t.id} className="hover:bg-white/[0.02]">
              <td className={`${TD} font-bold text-[#f4f8ff]`}>{t.name}</td>
              <td className={TD}>{t.care}</td>
              <td className={TD}>{t.date}</td>
              <td className={TD}>{t.time}</td>
              <td className={TD}>{t.guide}</td>
              <td className={TD}><Badge tone={t.status === 'Confirmed' ? 'green' : 'amber'}>{t.status}</Badge></td>
              <td className={TD}>
                <DemoButton
                  variant="x"
                  sm
                  onClick={() => {
                    actions.toggleTourStatus(t.id);
                    actions.toast('Tour status updated.');
                  }}
                >
                  {t.status === 'Confirmed' ? 'Reschedule' : 'Confirm'}
                </DemoButton>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
