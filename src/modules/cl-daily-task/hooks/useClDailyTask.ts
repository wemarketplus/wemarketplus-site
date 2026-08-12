import { useMemo } from 'react';
import { useListClLeadsQuery, type ClLeadRecord } from '@/modules/cl-leads';
import { useListClToursQuery, type ClTourRecord } from '@/modules/cl-tours';
import { CL_TOUR_STATUS } from '@/modules/cl-tours';
import { isOpenClLead } from '@/modules/cl-dashboard';
import {
  CL_DAILY_TASK_FETCH_LIMIT,
  CL_QUIET_AFTER_DAYS,
} from '../constants/clDailyTaskConstants';

export interface ClFollowUpRow {
  lead: ClLeadRecord;
  /** Whole days past due; 0 means it is due today. */
  daysOverdue: number;
}

export interface ClQuietRow {
  lead: ClLeadRecord;
  daysQuiet: number;
}

export interface ClDailyTaskData {
  /** `YYYY-MM-DD` the queue was built for. */
  today: string;
  followUpsDue: ClFollowUpRow[];
  toursToday: ClTourRecord[];
  goneQuiet: ClQuietRow[];
  leadName: (id: string | null) => string;
  totalItems: number;
  isLoading: boolean;
  isError: boolean;
}

/** `YYYY-MM-DD` in the user's own zone, never via toISOString. */
function localDateKey(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/** Whole days between two local day keys. */
function daysBetween(fromKey: string, toKey: string): number {
  const [fy, fm, fd] = fromKey.split('-').map(Number);
  const [ty, tm, td] = toKey.split('-').map(Number);
  const from = new Date(fy, (fm ?? 1) - 1, fd ?? 1).getTime();
  const to = new Date(ty, (tm ?? 1) - 1, td ?? 1).getTime();
  return Math.round((to - from) / 86_400_000);
}

/**
 * The CommunityLink Daily Task list — "This list builds itself: a lead's
 * follow-up date arriving, a tour scheduled for today, or a lead that's gone
 * quiet too long all show up automatically."
 *
 * Derived client-side from /cl/leads and /cl/tours rather than reusing
 * HospiceLink's /daily-queue: that endpoint assembles jobs, prospects and
 * referral sources — HL records with no CommunityLink counterpart — so it would
 * answer with a shape this screen cannot render. The three sections here are
 * exactly the three triggers the guide names, and nothing else, so the list
 * matches its own description.
 *
 * NOT self-scoped to the signed-in user, and that is deliberate for now: leads
 * carry `assignedTo`, but a CommunityLink tenant is a single community whose
 * marketers routinely cover for each other, and filtering to `assignedTo === me`
 * would silently hide an unassigned lead whose follow-up is overdue — the exact
 * row this screen exists to surface. Every row shows who it is assigned to
 * instead.
 */
export function useClDailyTask(): ClDailyTaskData {
  const leads = useListClLeadsQuery({
    page: 1,
    limit: CL_DAILY_TASK_FETCH_LIMIT,
  });
  const tours = useListClToursQuery({
    page: 1,
    limit: CL_DAILY_TASK_FETCH_LIMIT,
  });

  return useMemo(() => {
    const today = localDateKey(new Date());
    const leadRows = leads.data?.data ?? [];
    const openLeads = leadRows.filter(isOpenClLead);

    const nameOf = new Map(
      leadRows.map((lead) => [
        lead.id,
        [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() ||
          'Unnamed lead',
      ]),
    );

    // Due today OR earlier. String comparison is safe and zone-proof: both sides
    // are YYYY-MM-DD, which sorts lexicographically the same way it sorts by date.
    const followUpsDue = openLeads
      .filter((lead) => !!lead.followUpDate && lead.followUpDate <= today)
      .map((lead) => ({
        lead,
        daysOverdue: daysBetween(lead.followUpDate as string, today),
      }))
      .sort((a, b) => b.daysOverdue - a.daysOverdue);

    const toursToday = (tours.data?.data ?? [])
      .filter(
        (tour) =>
          tour.status === CL_TOUR_STATUS.Scheduled &&
          localDateKey(new Date(tour.scheduledAt)) === today,
      )
      .sort((a, b) => (a.scheduledAt < b.scheduledAt ? -1 : 1));

    /**
     * Quiet = nothing has touched the record in CL_QUIET_AFTER_DAYS.
     *
     * Keyed off `updatedAt` because that is the only recency signal the lead DTO
     * carries — there is no `lastContactedAt`. So an edit to a phone number counts
     * as contact, which understates the problem rather than inventing one; a lead
     * that appears here has genuinely not been touched at all.
     *
     * A lead with a future follow-up date is excluded: it is not neglected, it is
     * scheduled. Without that, every quiet lead would appear twice the moment its
     * date arrived.
     */
    const goneQuiet = openLeads
      .filter((lead) => {
        if (lead.followUpDate && lead.followUpDate > today) return false;
        const days = daysBetween(localDateKey(new Date(lead.updatedAt)), today);
        return days >= CL_QUIET_AFTER_DAYS;
      })
      .map((lead) => ({
        lead,
        daysQuiet: daysBetween(localDateKey(new Date(lead.updatedAt)), today),
      }))
      // Already listed above as a due follow-up — one row per lead per morning.
      .filter(({ lead }) => !followUpsDue.some((row) => row.lead.id === lead.id))
      .sort((a, b) => b.daysQuiet - a.daysQuiet);

    return {
      today,
      followUpsDue,
      toursToday,
      goneQuiet,
      leadName: (id: string | null) =>
        id ? (nameOf.get(id) ?? 'Lead') : 'No lead',
      totalItems:
        followUpsDue.length + toursToday.length + goneQuiet.length,
      isLoading: leads.isLoading || tours.isLoading,
      isError: leads.isError || tours.isError,
    };
  }, [
    leads.data,
    leads.isLoading,
    leads.isError,
    tours.data,
    tours.isLoading,
    tours.isError,
  ]);
}
