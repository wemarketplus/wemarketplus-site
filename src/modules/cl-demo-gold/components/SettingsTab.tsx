import { Card, DemoButton, Field, FI } from '@/shared/cl-demo';
import { PRICING_HREF } from '../constants/goldNav';
import { useGoldDemo } from '../hooks/useGoldDemo';

// Reproduces rSettings(): community details, subscription, and user-seats cards.
export function SettingsTab() {
  const { apts, actions } = useGoldDemo();

  return (
    <>
      <Card title="Community Settings">
        <div className="mb-3 grid grid-cols-2 gap-3">
          <Field label="Community Name">
            <input autoComplete="off" className={FI} defaultValue="Sunrise Senior Living" />
          </Field>
          <Field label="Total Units">
            <input autoComplete="off" className={FI} type="number" defaultValue={apts.length} />
          </Field>
          <Field label="Phone">
            <input autoComplete="off" className={FI} defaultValue="(214) 555-0100" />
          </Field>
          <Field label="City">
            <input autoComplete="off" className={FI} defaultValue="Dallas, TX" />
          </Field>
        </div>
        <DemoButton onClick={() => actions.toast('Settings saved!')}>Save Settings</DemoButton>
      </Card>

      <Card title="Subscription">
        <div className="mb-2.5 text-[13px] text-[#c8d6e8]">
          Plan: <strong className="text-[#f59e0b]">CommunityLink Gold CRM — $999/month</strong> (Demo)
        </div>
        <a
          href={PRICING_HREF}
          className="inline-block cursor-pointer rounded-full border-none bg-gradient-to-br from-[#f59e0b] to-[#d97706] px-[14px] py-[7px] text-[12px] font-bold text-[#06080e] no-underline"
        >
          View Pricing Plans
        </a>
      </Card>

      <Card title="User Seats">
        <div className="mb-2.5 text-[13px] text-[#c8d6e8]">5 of 15 seats used (Gold plan)</div>
        <DemoButton sm onClick={() => actions.toast('Invite sent! Check email.')}>+ Invite User</DemoButton>
      </Card>
    </>
  );
}
