import { useActiveProduct } from '@/modules/access';
import { Product } from '@/shared/types';
import { DailyQueuePage } from './DailyQueuePage';
import { ClDailyTasksPage } from './ClDailyTasksPage';

/**
 * `/daily-tasks` for whichever dashboard the user is standing in.
 *
 * The two products build the day from entirely different tables — HospiceLink from
 * tasks/jobs/appointments/prospects/referral sources, CommunityLink from cl_leads
 * and cl_tours — so this picks the page rather than one page branching internally.
 * A single component holding both would carry two sets of queries, one of which
 * always 403s or returns nothing, and two vocabularies for "overdue".
 *
 * The route lives OUTSIDE both product groups in router.tsx precisely so this
 * switch can happen; putting `/daily-tasks` inside the HospiceLink group is what
 * made a CommunityLink marketer following their guide's first instruction land on
 * the HospiceLink dashboard instead.
 */
export function DailyTasksRoute() {
  const { activeProduct } = useActiveProduct();
  return activeProduct === Product.CommunityLink ? (
    <ClDailyTasksPage />
  ) : (
    <DailyQueuePage />
  );
}
