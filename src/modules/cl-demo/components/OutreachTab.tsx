import { Card } from './Card';
import { Badge } from './Badge';
import { DemoButton } from './DemoButton';
import { TBL, TD, TH } from '../constants/clDemoStyles';
import { useClDemo } from '../hooks/useClDemo';

// Outreach Log tab — reproduces rOutreach(): a read-only activity table with a
// shortcut to the GPS Check-In tab.
export function OutreachTab() {
  const { outreach, actions } = useClDemo();

  return (
    <Card
      title="Outreach Activity Log"
      action={
        <DemoButton sm onClick={() => actions.setTab('gps')}>
          + Log Visit
        </DemoButton>
      }
    >
      <table className={TBL}>
        <thead>
          <tr>
            {['Date', 'Location', 'Contact', 'Type', 'Miles', 'Notes'].map((h) => (
              <th key={h} className={TH}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {outreach.map((o) => (
            <tr key={o.id} className="hover:bg-white/[0.02]">
              <td className={TD}>{o.date}</td>
              <td className={`${TD} font-bold text-[#f4f8ff]`}>{o.location}</td>
              <td className={TD}>{o.contact}</td>
              <td className={TD}><Badge tone="blue">{o.type}</Badge></td>
              <td className={TD}>{o.miles}</td>
              <td className={`${TD} max-w-[200px] text-[11px] text-[#6b7fa3]`}>{o.notes}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
