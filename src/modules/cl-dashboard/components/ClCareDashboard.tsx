import { ClipboardList, NotebookPen, Stethoscope } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, CardContent } from '@/shared/ui/core';

/** Where a care persona's day actually happens, per the guide's Steps 3–5. */
const SHORTCUTS = [
  {
    to: '/tasks',
    icon: ClipboardList,
    label: 'Tasks',
    detail: 'Medication reminders and check-in rounds',
  },
  {
    to: '/activity-notes',
    icon: NotebookPen,
    label: 'Activity notes',
    detail: 'Wellness checks and family updates, until the care log ships',
  },
] as const;

/**
 * The Nurse / Caregiver dashboard on CommunityLink.
 *
 * The guide describes this screen in the FUTURE tense — "Your Dashboard will be
 * scoped to resident wellness checks and your assigned care tasks" — and its own
 * preamble warns that the Resident Care Log "may not be live yet". So this does
 * not fabricate wellness-check metrics: there is no resident-care resource in the
 * API to count, and inventing tiles over data that does not exist is how a
 * dashboard starts lying.
 *
 * Instead it says plainly what is coming and hands over the two screens the guide
 * names as the interim workflow. That is a deliberately small screen, and it beats
 * the alternative it replaces: without this case these two roles fell through to
 * the Sales Dashboard and were shown lead-conversion and tour figures that are
 * neither their job nor, for a caregiver, their business.
 */
export function ClCareDashboard() {
  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="flex flex-wrap items-start gap-3 px-6 py-5">
          <span className="rounded-[10px] bg-primary/[0.08] p-2 text-primary">
            <Stethoscope className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-foreground">
              Resident care log — coming soon
            </h2>
            <p className="mt-1 text-[12.5px] leading-relaxed text-muted">
              Wellness checks, incident notes and family updates tied to a
              specific resident will live here. Until it ships, log them in
              Activity notes and keep your rounds in Tasks.
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {SHORTCUTS.map(({ to, icon: Icon, label, detail }) => (
          <Link
            key={to}
            to={to}
            className="rounded-[14px] border border-border/[0.09] bg-surface px-5 py-5 transition-colors hover:border-primary/40"
          >
            <span className="flex h-[30px] w-[30px] items-center justify-center rounded-[9px] bg-primary/[0.08] text-primary">
              <Icon className="h-4 w-4" />
            </span>
            <p className="mt-3 text-[15px] font-bold text-foreground">{label}</p>
            <p className="mt-1 text-[12.5px] leading-snug text-muted">{detail}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
