import { Card, DemoButton, Field, FI } from '@/shared/cl-demo';
import { PRICING_HREF } from '../constants/maxNav';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rSettings(): community details, subscription, and user-seats cards.
export function SettingsTab() {
  const { apts, actions } = useMaxDemo();
  return (
    <>
      <Card title="Community Settings">
        <div className="mb-3 grid grid-cols-2 gap-3">
          <Field label="Community Name"><input className={FI} defaultValue="Sunrise Senior Living" /></Field>
          <Field label="Total Units"><input className={FI} type="number" defaultValue={apts.length} /></Field>
          <Field label="Phone"><input className={FI} defaultValue="(214) 555-0100" /></Field>
          <Field label="City"><input className={FI} defaultValue="Dallas, TX" /></Field>
        </div>
        <DemoButton onClick={() => actions.toast('Settings saved!')}>Save Settings</DemoButton>
      </Card>
      <Card title="Subscription">
        <div className="mb-2.5 text-[13px] text-[#c8d6e8]">Plan: <strong className="text-[#4fc87a]">CommunityLink Max CRM — $1,999/month</strong> (Demo)</div>
        <a href={PRICING_HREF} className="inline-block cursor-pointer rounded-full border-none bg-gradient-to-br from-[#f59e0b] to-[#d97706] px-[14px] py-[7px] text-[12px] font-bold text-[#06080e] no-underline">View Pricing Plans</a>
      </Card>
      <Card title="User Seats">
        <div className="mb-2.5 text-[13px] text-[#c8d6e8]">5 of 30 seats used (Max plan)</div>
        <DemoButton sm onClick={() => actions.toast('Invite sent! Check email.')}>+ Invite User</DemoButton>
      </Card>
    </>
  );
}
