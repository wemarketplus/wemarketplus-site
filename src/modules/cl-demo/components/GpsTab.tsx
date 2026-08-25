import { useState } from 'react';
import { Badge, Card, DemoButton, Field, FG, FI, todayIso } from '@/shared/cl-demo';
import { GPS_VISIT_TYPES } from '../constants/clDemoData';
import { useClDemo } from '../hooks/useClDemo';
import { useGpsCapture } from '../hooks/useGpsCapture';

// GPS Check-In tab — reproduces rGPS(): a capture form with a live "map"
// placeholder plus a Recent Check-Ins list.
export function GpsTab() {
  const { outreach, actions } = useClDemo();
  const { coords, capture } = useGpsCapture();
  const [org, setOrg] = useState('');
  const [person, setPerson] = useState('');
  const [type, setType] = useState<string>(GPS_VISIT_TYPES[0]);
  const [miles, setMiles] = useState('');
  const [notes, setNotes] = useState('');

  const log = () => {
    if (!org.trim()) {
      actions.toast('Facility name required.', true);
      return;
    }
    actions.addOutreach({
      date: todayIso(),
      location: org.trim(),
      contact: person,
      type,
      miles: parseFloat(miles) || 0,
      notes,
    });
    actions.toast('✓ Check-in logged: ' + org.trim());
    setOrg('');
    setPerson('');
    setMiles('');
    setNotes('');
  };

  const recent = outreach.slice(0, 4);

  return (
    <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
      <Card title="Log Visit" action={<Badge tone="green">● GPS Ready</Badge>}>
        <div className="mb-[14px] flex h-[180px] items-center justify-center rounded-[12px] border border-[#f59e0b]/[0.12] bg-[#060e1b]">
          <div className="text-center">
            <div className="mx-auto mb-3 h-3.5 w-3.5 animate-pulse rounded-full bg-[#f59e0b] shadow-[0_0_0_4px_rgba(245,158,11,0.25)]" />
            <div className="text-[12px] font-bold text-[#f59e0b]">Location Active</div>
            <div className="mt-1 text-[11px] text-[#4b6278]">{coords || 'Click Capture GPS'}</div>
          </div>
        </div>
        <div className={FG}>
          <Field label="Facility *">
            <input autoComplete="off" className={FI} value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Parkland Hospital" />
          </Field>
          <Field label="Contact">
            <input autoComplete="off" className={FI} value={person} onChange={(e) => setPerson(e.target.value)} placeholder="Dr. Amanda Chen" />
          </Field>
          <Field label="Visit Type">
            <select autoComplete="off" className={FI} value={type} onChange={(e) => setType(e.target.value)}>
              {GPS_VISIT_TYPES.map((t) => <option key={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="Miles Driven">
            <input autoComplete="off" className={FI} type="number" value={miles} onChange={(e) => setMiles(e.target.value)} placeholder="12" />
          </Field>
          <Field label="GPS Coordinates" wide>
            <input autoComplete="off" className={FI} value={coords} readOnly placeholder="Click Capture GPS…" />
          </Field>
          <Field label="Notes" wide>
            <textarea autoComplete="off" className={`${FI} min-h-[60px] resize-y`} rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="What happened? Next steps?" />
          </Field>
        </div>
        <div className="mt-1 flex gap-2">
          <DemoButton variant="x" onClick={capture}>📍 Capture GPS</DemoButton>
          <DemoButton onClick={log}>Log Check-In</DemoButton>
        </div>
      </Card>

      <Card title="Recent Check-Ins">
        {recent.map((o) => (
          <div key={o.id} className="border-b border-white/[0.04] py-2">
            <div className="text-[12px] font-bold text-[#f4f8ff]">{o.location}</div>
            <div className="text-[10px] text-[#4b6278]">{o.date} • {o.contact} • {o.miles} mi</div>
            <div className="mt-0.5 text-[11px] text-[#6b7fa3]">{o.notes}</div>
          </div>
        ))}
      </Card>
    </div>
  );
}
