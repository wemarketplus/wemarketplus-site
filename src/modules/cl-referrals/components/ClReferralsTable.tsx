import { Star } from 'lucide-react';
import { DataTable, type Column } from '@/shared/ui/data-display';
import type { SeniorLivingReferral } from '../types/clReferralsTypes';
import { SOURCE_LABEL } from '../constants/clReferralsConstants';
import { ratingToneClass } from '../utils/ratingClass';

const columns: ReadonlyArray<Column<SeniorLivingReferral>> = [
  {
    key: 'contact',
    header: 'Contact',
    cell: (r) => (
      <div>
        <p className="font-bold text-[#111]">{r.name}</p>
        <p className="text-[11px] text-[#667]">
          {r.email} · {r.phone}
        </p>
      </div>
    ),
  },
  { key: 'organization', header: 'Organization', cell: (r) => r.organization },
  { key: 'source', header: 'Source', cell: (r) => SOURCE_LABEL[r.source] },
  {
    key: 'rating',
    header: 'Rating',
    cell: (r) => (
      <span className={`inline-flex items-center gap-1 ${ratingToneClass(r.rating)}`}>
        <Star className="h-3.5 w-3.5 fill-current" />
        {r.rating}/5
      </span>
    ),
  },
];

export function ClReferralsTable({
  items,
}: {
  items: readonly SeniorLivingReferral[];
}) {
  return <DataTable columns={columns} rows={items} rowKey={(r) => r.id} />;
}
