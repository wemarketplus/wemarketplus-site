import { useState } from 'react';
import { Card } from '@/shared/cl-demo';
import { DemoButton } from '@/shared/cl-demo';
import { Field } from '@/shared/cl-demo';
import { COMMUNITY_DEFAULTS } from '../constants/clDemoData';
import { PRICING_HREF } from '../constants/clDemoNav';
import { FG, FI } from '@/shared/cl-demo';
import { useClDemo } from '../hooks/useClDemo';

// Settings tab — reproduces rSettings(): community form, subscription card, and
// admin-only user management.
export function SettingsTab() {
  const { role, actions } = useClDemo();
  const [name, setName] = useState<string>(COMMUNITY_DEFAULTS.name);
  const [phone, setPhone] = useState<string>(COMMUNITY_DEFAULTS.phone);
  const [city, setCity] = useState<string>(COMMUNITY_DEFAULTS.city);
  const [state, setState] = useState<string>(COMMUNITY_DEFAULTS.state);
  const [address, setAddress] = useState<string>(COMMUNITY_DEFAULTS.address);

  return (
    <>
      <Card title="Community Settings">
        <div className={FG}>
          <Field label="Community Name"><input className={FI} value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Phone"><input className={FI} value={phone} onChange={(e) => setPhone(e.target.value)} /></Field>
          <Field label="City"><input className={FI} value={city} onChange={(e) => setCity(e.target.value)} /></Field>
          <Field label="State"><input className={FI} value={state} onChange={(e) => setState(e.target.value)} /></Field>
          <Field label="Address" wide><input className={FI} value={address} onChange={(e) => setAddress(e.target.value)} /></Field>
        </div>
        <DemoButton onClick={() => actions.toast('Settings saved: ' + name)}>Save Settings</DemoButton>
      </Card>

      <Card title="Subscription">
        <div className="mb-2.5 text-[13px] text-[#c8d6e8]">
          Plan: <strong className="text-[#f59e0b]">CommunityLink Pro CRM — $499/month</strong> (Demo)
        </div>
        <a
          href={PRICING_HREF}
          className="inline-block cursor-pointer rounded-full bg-gradient-to-br from-[#f59e0b] to-[#d97706] px-[14px] py-[7px] text-[12px] font-bold text-[#06080e] no-underline"
        >
          View Pricing Plans
        </a>
      </Card>

      <Card title="User Management" className={role === 'admin' ? '' : 'pointer-events-none opacity-50'}>
        <div className="mb-2.5 text-[13px] text-[#c8d6e8]">Seats: 3 of 5 used (Pro plan)</div>
        {role === 'admin' ? (
          <DemoButton sm onClick={() => actions.toast('Invite sent! Check email.')}>+ Invite User</DemoButton>
        ) : (
          <div className="text-[12px] text-[#6b7fa3]">Admin only</div>
        )}
      </Card>
    </>
  );
}
