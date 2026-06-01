// Fixtures shared across modules (notifications, subscription, etc.).
// See hospicelinkFixtures.ts header for the philosophy.

import {
  SubscriptionStatus,
  Tier,
  Product,
  type AppNotification,
} from '@/shared/types';

export interface SubscriptionFixture {
  product: Product;
  plan: Tier;
  status: SubscriptionStatus;
  currentPeriodEnd: string;
  scheduledDeleteAt?: string;
  organizationName: string;
}

export const SUBSCRIPTION_FIXTURE: SubscriptionFixture = {
  product: Product.HospiceLink,
  plan: Tier.Pro,
  status: SubscriptionStatus.Active,
  currentPeriodEnd: '2026-06-23T00:00:00Z',
  organizationName: 'Bay Area Hospice Group',
};

export const NOTIFICATIONS_FIXTURE: readonly AppNotification[] = [
  {
    id: 'nf-001',
    category: 'alert',
    title: 'Cold source flagged',
    body: 'Marcus DeLeon at Trinity Senior Living is overdue by 44 days.',
    createdAt: '2026-05-24T13:10:00Z',
    read: false,
    href: '/referrals',
  },
  {
    id: 'nf-002',
    category: 'task',
    title: 'Sign POA paperwork',
    body: 'Walter Kim — overdue by 2 days.',
    createdAt: '2026-05-24T11:55:00Z',
    read: false,
    href: '/reminders',
  },
  {
    id: 'nf-003',
    category: 'mention',
    title: 'Avery mentioned you in a note',
    body: 'On Eleanor Whitmore — “let’s coordinate the in-home assessment”',
    createdAt: '2026-05-23T23:08:00Z',
    read: true,
    href: '/prospects',
  },
  {
    id: 'nf-004',
    category: 'system',
    title: 'HIPAA audit log exported',
    body: 'Your monthly compliance bundle is ready.',
    createdAt: '2026-05-23T17:30:00Z',
    read: true,
    href: '/compliance',
  },
];
