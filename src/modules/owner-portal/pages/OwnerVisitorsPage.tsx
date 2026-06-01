import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatRelative } from '@/shared/utils/dateFormatter';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_VISITORS } from '../constants/ownerFixtures';
import type { OwnerVisitor } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerVisitor>> = [
  { key: 'source', header: 'Source', cell: (v) => v.source },
  {
    key: 'landing',
    header: 'Landing page',
    cell: (v) => <span className="font-mono text-[11px] text-[#667]">{v.landingPage}</span>,
  },
  {
    key: 'session',
    header: 'Session',
    cell: (v) => `${Math.round(v.sessionLengthSec / 60)}m ${v.sessionLengthSec % 60}s`,
  },
  {
    key: 'converted',
    header: 'Converted',
    cell: (v) =>
      v.converted ? <Pill tone="g">Converted</Pill> : <Pill tone="b">Browsing</Pill>,
  },
  { key: 'when', header: 'When', cell: (v) => formatRelative(v.visitedAt) },
];

export function OwnerVisitorsPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Website visitors"
        description="The marketing-site funnel in real time."
      />
      <DataTable columns={columns} rows={OWNER_VISITORS} rowKey={(v) => v.id} />
    </div>
  );
}
