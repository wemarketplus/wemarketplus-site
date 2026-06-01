import { Product } from '@/shared/types';
import type {
  DashboardActivityItem,
  DashboardStatCard,
} from '../types/dashboardTypes';

// Product-specific stat tiles. Replace each block with real metrics once the
// backend exposes /dashboard/{hospicelink,communitylink} endpoints.
export const HOSPICELINK_STATS: readonly DashboardStatCard[] = [
  { id: 'inquiries', label: 'New inquiries', value: '14', hint: 'This week', tone: 'primary' },
  { id: 'pending', label: 'Pending admission', value: '6', hint: '2 due today', tone: 'warning' },
  { id: 'admitted', label: 'Admitted', value: '11', hint: 'MTD', tone: 'success' },
  { id: 'cold-sources', label: 'Cold sources', value: '3', hint: 'Action needed', tone: 'destructive' },
];

export const COMMUNITYLINK_STATS: readonly DashboardStatCard[] = [
  { id: 'occupancy', label: 'Occupancy', value: '93%', hint: '+1.2 pp vs LM', tone: 'success' },
  { id: 'tours', label: 'Tours this week', value: '12', hint: '4 today', tone: 'primary' },
  { id: 'move-ins', label: 'Move-ins MTD', value: '5', hint: 'Target 7', tone: 'warning' },
  { id: 'make-ready', label: 'Make-ready units', value: '3', hint: '1 overdue', tone: 'destructive' },
];

export const STATS_BY_PRODUCT: Record<Product, readonly DashboardStatCard[]> = {
  [Product.HospiceLink]: HOSPICELINK_STATS,
  [Product.CommunityLink]: COMMUNITYLINK_STATS,
};

export const ACTIVITY_BY_PRODUCT: Record<Product, readonly DashboardActivityItem[]> = {
  [Product.HospiceLink]: [
    {
      id: 'a-1',
      title: 'New inquiry — Eleanor Whitmore',
      detail: 'From Mercy Hospital · assigned to Avery Cole',
      occurredAt: '2026-05-24T17:10:00Z',
    },
    {
      id: 'a-2',
      title: 'Dr. Patel logged a referral',
      detail: 'Bayview Internal Medicine · prospect added',
      occurredAt: '2026-05-24T15:32:00Z',
    },
    {
      id: 'a-3',
      title: 'Cold source flagged',
      detail: 'Trinity Senior Living overdue by 44 days',
      occurredAt: '2026-05-24T13:10:00Z',
    },
  ],
  [Product.CommunityLink]: [
    {
      id: 'a-1',
      title: 'Tour booked — Helen Vasquez',
      detail: 'Tuesday 10:00am · in-person',
      occurredAt: '2026-05-24T17:00:00Z',
    },
    {
      id: 'a-2',
      title: 'Unit 202 make-ready 62% complete',
      detail: 'Marisol Quinto · target 5/27',
      occurredAt: '2026-05-24T15:00:00Z',
    },
    {
      id: 'a-3',
      title: 'Maintenance ticket opened',
      detail: 'Unit 401 — leaky bathroom faucet',
      occurredAt: '2026-05-24T14:00:00Z',
    },
  ],
};
