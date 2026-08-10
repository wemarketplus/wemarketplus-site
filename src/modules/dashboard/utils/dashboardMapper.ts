// Lucide is the icon system the reference design uses (24px grid, 2px stroke).
import {
  CalendarCheck,
  ClipboardList,
  Inbox,
  MoveRight,
  Receipt,
  UserCheck,
  Users,
} from 'lucide-react';
import { Product } from '@/shared/types';
import type {
  DashboardActivityItem,
  DashboardStatCard,
  DashboardSummary,
} from '../types/dashboardTypes';

// Maps the live tenant summary (GET /dashboard/summary) onto the product-specific
// KPI tiles the dashboard already renders. Keeps the same four-tile layout but
// feeds real, tenant-scoped numbers. Stage keys mirror the backend ProspectStage
// enum (wemarketplus-backend/src/prospects/prospects.constants).
function stage(summary: DashboardSummary, key: string): number {
  return summary.prospects.byStage[key] ?? 0;
}

/**
 * The tiles read CANONICAL stages.
 *
 * They previously counted `inquiry`, `pending` and `evaluation` — all three of
 * which are LEGACY stages that `moveStage` rejects as targets and that nothing
 * in the current flow writes. Both tiles therefore read 0 for every tenant on
 * the current pipeline, permanently, which looks like an empty pipeline rather
 * than a broken tile.
 */
function hospicelinkStats(summary: DashboardSummary): DashboardStatCard[] {
  return [
    {
      id: 'new-referrals',
      label: 'New referrals',
      icon: Inbox,
      value: String(stage(summary, 'new_referral')),
      hint: 'Awaiting eligibility check',
      tone: 'primary',
    },
    {
      id: 'in-progress',
      label: 'Working',
      icon: ClipboardList,
      // The three middle stages of the admit pipeline — everything that is
      // being actively worked but not yet closed either way.
      value: String(
        stage(summary, 'eligibility') +
          stage(summary, 'face_to_face') +
          stage(summary, 'consent_order'),
      ),
      hint: `${summary.tasks.open} open task${summary.tasks.open === 1 ? '' : 's'}`,
      tone: 'warning',
    },
    {
      id: 'admitted',
      label: 'Admitted',
      icon: UserCheck,
      value: String(stage(summary, 'admitted')),
      hint: `${summary.prospects.total} total`,
      tone: 'success',
    },
    {
      id: 'overdue-invoices',
      label: 'Overdue invoices',
      icon: Receipt,
      value: String(summary.invoices.overdue),
      hint: summary.invoices.overdue > 0 ? 'Action needed' : 'All current',
      tone: summary.invoices.overdue > 0 ? 'destructive' : 'success',
    },
  ];
}

function communitylinkStats(summary: DashboardSummary): DashboardStatCard[] {
  return [
    {
      id: 'leads',
      label: 'Active leads',
      icon: Users,
      value: String(summary.prospects.total),
      hint: `${stage(summary, 'inquiry')} new`,
      tone: 'primary',
    },
    {
      id: 'tours',
      label: 'In evaluation',
      icon: CalendarCheck,
      value: String(stage(summary, 'evaluation') + stage(summary, 'pending')),
      hint: `${summary.tasks.open} open task${summary.tasks.open === 1 ? '' : 's'}`,
      tone: 'warning',
    },
    {
      id: 'move-ins',
      label: 'Move-ins',
      icon: MoveRight,
      value: String(stage(summary, 'admitted')),
      hint: 'Admitted stage',
      tone: 'success',
    },
    {
      id: 'overdue-invoices',
      label: 'Overdue invoices',
      icon: Receipt,
      value: String(summary.invoices.overdue),
      hint: summary.invoices.overdue > 0 ? 'Action needed' : 'All current',
      tone: summary.invoices.overdue > 0 ? 'destructive' : 'success',
    },
  ];
}

export function mapSummaryToStats(
  summary: DashboardSummary,
  product: Product,
): DashboardStatCard[] {
  return product === Product.CommunityLink
    ? communitylinkStats(summary)
    : hospicelinkStats(summary);
}

/**
 * Turns an audit action or resource into a readable label.
 *
 * Audit actions are stored SHOUTING ("MOVE_PIPELINE_STAGE"), so lowercase first —
 * otherwise the per-word capitalisation is a no-op and the feed shouts. Product
 * table prefixes (`hl_` HospiceLink, `cl_` CommunityLink) are stripped so
 * "hl_leads" reads as "Leads" rather than "Hl Leads".
 */
function titleize(value: string): string {
  return value
    .toLowerCase()
    .replace(/^(hl|cl)_/, '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

export function mapSummaryToActivity(
  summary: DashboardSummary,
): DashboardActivityItem[] {
  return summary.recentActivity.map((entry) => {
    const resource = entry.resource ? titleize(entry.resource) : 'Record';
    return {
      id: entry.id,
      title: `${titleize(entry.action)} — ${resource}`,
      // The raw resource uuid was noise; the actor is the useful second line.
      detail: entry.actorName,
      actorName: entry.actorName,
      actorEmail: entry.actorEmail,
      occurredAt: entry.createdAt,
    };
  });
}
