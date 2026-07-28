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

function hospicelinkStats(summary: DashboardSummary): DashboardStatCard[] {
  return [
    {
      id: 'inquiries',
      label: 'New inquiries',
      icon: Inbox,
      value: String(stage(summary, 'inquiry')),
      hint: 'Inquiry stage',
      tone: 'primary',
    },
    {
      id: 'pending',
      label: 'Pending admission',
      icon: ClipboardList,
      value: String(stage(summary, 'pending') + stage(summary, 'evaluation')),
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

// Turns an audit action + resource ("create" / "prospect") into a readable title.
function titleize(value: string): string {
  return value
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
      detail: entry.resourceId ? `Ref ${entry.resourceId}` : resource,
      occurredAt: entry.createdAt,
    };
  });
}
