import { useActiveProduct } from '@/modules/access';
import { ClCalendarPage } from '@/modules/cl-calendar';
import { Product } from '@/shared/types';
import { AppointmentsPage } from './AppointmentsPage';

/**
 * `/appointments` — "Calendar" in both sidebars — for whichever dashboard the
 * user is standing in. Same shape as DailyTasksRoute, and for the same reason:
 * the two products build the day out of entirely different tables.
 *
 * WHY THIS EXISTS. One screen used to serve both, and it could not: every row in
 * `hl_appointments` requires a `jobId` (CreateAppointmentDto.jobId is a required
 * UUID), jobs live behind `@RequireProduct(HospiceLink)` + `@Roles(...HL_MARKETING_ROLES)`
 * on JobsController, and the Job picker is the first field of the schedule form.
 * So on CommunityLink the request behind that picker answers 403, the dropdown
 * renders nothing but its placeholder, and the form cannot be submitted at all —
 * the "Job dropdown does not display any options" report. Nothing about the
 * FRONTEND mapping was wrong: `jobsPage?.data` is the right read, and on a
 * HospiceLink-entitled tenant the same code fills the list correctly.
 *
 * CommunityLink's own calendar was already built for exactly this — tours,
 * facility visits and physician lunches over /cl/tours and /cl/outreach-visits,
 * which is what its guide describes — and was exported but never routed, so no
 * amount of fixing the HospiceLink form would have reached it.
 *
 * TWO CONSEQUENCES, both deliberate:
 *
 *  - The calendar is now PRODUCT-SCOPED, like every other screen in the app. A
 *    dual-product tenant sees CommunityLink tours and visits on the CommunityLink
 *    dashboard and HospiceLink appointments on the HospiceLink one, switching with
 *    the product switcher in the header, instead of one product's calendar quietly
 *    showing the other product's records.
 *  - CommunityLink's page loads a page of tours and visits and buckets them by
 *    day rather than querying the visible month (neither endpoint takes a date
 *    range — see CL_CALENDAR_FETCH_LIMIT). Within the fetch window that is
 *    correct and instant; beyond it, a distant month renders empty. Adding
 *    `from`/`to` to those two endpoints is the fix, and is the reason this note
 *    names the limitation rather than leaving it to be discovered.
 */
export function CalendarRoute() {
  const { activeProduct } = useActiveProduct();
  return activeProduct === Product.CommunityLink ? (
    <ClCalendarPage />
  ) : (
    <AppointmentsPage />
  );
}
