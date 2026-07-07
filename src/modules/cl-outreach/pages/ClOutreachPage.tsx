import { cn } from '@/shared/utils/cn';
import { OUTREACH_VIEWS } from '../constants/clOutreachConstants';
import { useOutreach } from '../hooks/useOutreach';
import { useOutreachView } from '../hooks/useOutreachView';
import { CheckInList } from '../components/CheckInList';
import { MileageList } from '../components/MileageList';

const HEADER_BY_VIEW = {
  checkin: {
    title: 'GPS check-in',
    subtitle: 'Field visits logged with GPS location and timestamp.',
  },
  mileage: {
    title: 'Mileage',
    subtitle: 'Reimbursable miles captured from field visits.',
  },
  log: {
    title: 'Outreach log',
    subtitle: 'Full history of referral-source visits and touchpoints.',
  },
} as const;

export function ClOutreachPage() {
  const { view, setView } = useOutreachView();
  const { checkIns, mileage, log } = useOutreach();
  const header = HEADER_BY_VIEW[view];

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">{header.title}</h1>
        <p className="text-sm text-muted">{header.subtitle}</p>
      </header>

      <nav className="flex flex-wrap gap-1.5">
        {OUTREACH_VIEWS.map((v) => (
          <button
            key={v.value}
            type="button"
            onClick={() => setView(v.value)}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              view === v.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
            )}
          >
            {v.label}
          </button>
        ))}
      </nav>

      {view === 'checkin' && <CheckInList items={checkIns} />}
      {view === 'mileage' && <MileageList entries={mileage} />}
      {view === 'log' && <CheckInList items={log} />}
    </div>
  );
}
