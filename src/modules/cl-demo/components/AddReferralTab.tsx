import { useState } from 'react';
import { Card } from '@/shared/cl-demo';
import { DemoButton } from '@/shared/cl-demo';
import { Field } from '@/shared/cl-demo';
import { REFERRAL_TYPES } from '../constants/clDemoData';
import { FG, FI } from '@/shared/cl-demo';
import { useClDemo } from '../hooks/useClDemo';

// Add Referral Source tab — reproduces rAddRef() + saveRef().
export function AddReferralTab() {
  const { actions } = useClDemo();
  const [name, setName] = useState('');
  const [org, setOrg] = useState('');
  const [type, setType] = useState<string>(REFERRAL_TYPES[0]);
  const [phone, setPhone] = useState('');
  const [email, setEmail] = useState('');
  const [city, setCity] = useState('');
  const [notes, setNotes] = useState('');

  const save = () => {
    if (!name.trim()) {
      actions.toast('Name required.', true);
      return;
    }
    actions.addReferral({ name: name.trim(), type, org, phone });
    actions.toast('Referral source added: ' + name.trim());
    actions.setTab('refs');
  };

  return (
    <Card
      title="Add Referral Source"
      action={
        <DemoButton variant="x" sm onClick={() => actions.setTab('refs')}>
          Cancel
        </DemoButton>
      }
    >
      <div className={FG}>
        <Field label="Contact Name *">
          <input className={FI} value={name} onChange={(e) => setName(e.target.value)} placeholder="Dr. Amanda Chen" />
        </Field>
        <Field label="Organization">
          <input className={FI} value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Dallas Medical Group" />
        </Field>
        <Field label="Type">
          <select className={FI} value={type} onChange={(e) => setType(e.target.value)}>
            {REFERRAL_TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
        </Field>
        <Field label="Phone">
          <input className={FI} type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="(214) 555-0100" />
        </Field>
        <Field label="Email">
          <input className={FI} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@org.com" />
        </Field>
        <Field label="City">
          <input className={FI} value={city} onChange={(e) => setCity(e.target.value)} placeholder="Dallas" />
        </Field>
        <Field label="Notes" wide>
          <textarea className={`${FI} min-h-[72px] resize-y`} rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="How we met, relationship notes…" />
        </Field>
      </div>
      <DemoButton onClick={save}>Save Source</DemoButton>
    </Card>
  );
}
