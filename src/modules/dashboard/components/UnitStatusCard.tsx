import { Card, CardContent } from '@/shared/ui/core';
import { Pill, SectionHeader } from '@/shared/ui/data-display';
import { DashboardCardAction } from './DashboardCardAction';
import {
  APARTMENT_STATUS,
  APARTMENT_STATUS_LABELS,
  APARTMENT_STATUS_PILL,
} from '@/modules/cl-operations';
import type { DashboardOperations } from '../types/dashboardTypes';

/**
 * The unit-status breakdown, in the order the client's reference design lists it:
 * occupied first (the number that pays), then everything that is not yet earning.
 *
 * Keyed off the SAME status constants the Apartment Inventory table uses, so a
 * label or a colour changes in one place. The counts come from the server's
 * `countUnitStatuses`, which is also what the Occupancy summary report reads —
 * this card and that report cannot disagree.
 */
const ROWS: ReadonlyArray<{
  status: (typeof APARTMENT_STATUS)[keyof typeof APARTMENT_STATUS];
  key: keyof DashboardOperations['units'];
}> = [
  { status: APARTMENT_STATUS.Occupied, key: 'occupied' },
  { status: APARTMENT_STATUS.Available, key: 'available' },
  { status: APARTMENT_STATUS.Reserved, key: 'reserved' },
  { status: APARTMENT_STATUS.OnNotice, key: 'onNotice' },
  { status: APARTMENT_STATUS.MakeReady, key: 'makeReady' },
  { status: APARTMENT_STATUS.Maintenance, key: 'maintenance' },
  { status: APARTMENT_STATUS.Offline, key: 'offline' },
];

/**
 * "Unit Status" — the at-a-glance half of the Executive Director's dashboard,
 * beside Operations Alerts.
 *
 * Every status renders, including the zeroes. A director reading this is checking
 * a shape they already hold in their head ("we should have two on notice"), and a
 * card that hides empty rows changes shape week to week — which makes it slower to
 * read, not faster. The zeroes are also the reassuring part.
 */
export function UnitStatusCard({
  operations,
}: {
  operations: DashboardOperations;
}) {
  const { units } = operations;

  return (
    <Card>
      <CardContent className="pt-6">
        <SectionHeader
          title="Unit status"
          subtitle={`${units.total} unit${units.total === 1 ? '' : 's'} across the community`}
          actions={
            <DashboardCardAction
              to="/operations/inventory"
              label="View all"
              ariaLabel="View all units in apartment inventory"
            />
          }
        />
        <ul className="divide-y divide-border/[0.07]">
          {ROWS.map(({ status, key }) => (
            <li key={status} className="flex items-center gap-3 py-2.5">
              <Pill tone={APARTMENT_STATUS_PILL[status]}>
                {APARTMENT_STATUS_LABELS[status]}
              </Pill>
              <span className="ml-auto text-[18px] font-bold leading-none text-foreground">
                {units[key]}
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
