import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Building2,
  Contact,
  CreditCard,
  UserPlus,
  Users,
  type LucideIcon,
} from 'lucide-react';
import { useAppSelector } from '@/app/hooks';
import { SubscriptionStatus } from '@/shared/types';
import { useListContactsQuery } from '@/modules/contacts/api/contactsApi';
import { useListProspectsQuery } from '@/modules/prospects/api/prospectsApi';
import { useListUsersQuery } from '@/modules/users/api/usersApi';
import { useGetSubscriptionQuery } from '@/modules/billing/api/billingApi';
import { useGetMyTenantQuery } from '@/modules/settings/api/settingsApi';

export interface ChecklistStep {
  id: string;
  icon: LucideIcon;
  // Outcome-framed label — the value the tenant gets, not the mechanic.
  title: string;
  description: string;
  to: string;
  ctaLabel: string;
  done: boolean;
}

interface OnboardingChecklist {
  steps: ChecklistStep[];
  completed: number;
  total: number;
  // 0-100, for the progress bar.
  progress: number;
  isComplete: boolean;
  isLoading: boolean;
  // True only when we have real data and the tenant still has open steps —
  // the card should not render otherwise (and never once dismissed).
  isVisible: boolean;
  // True for one session when the tenant finishes the last step while the card
  // is open, so the card can swap the list for a celebration. It does not
  // persist across reloads — a fully complete checklist stays hidden after that.
  justCompleted: boolean;
  dismiss: () => void;
}

// localStorage is keyed per tenant so switching accounts (or a fresh tenant on
// the same browser) gets its own dismissal state.
const dismissKey = (tenantId: string) => `onboarding-checklist:dismissed:${tenantId}`;

// Derives the onboarding checklist entirely from queries the app already runs
// (contacts/prospects/users lists, subscription, tenant profile). No new
// backend endpoints. Each step auto-checks from real tenant data so the list
// reflects genuine progress rather than a stored flag.
export function useOnboardingChecklist(): OnboardingChecklist {
  const tenantId = useAppSelector((s) => s.auth.user?.tenantId) ?? '';

  // limit: 1 — we only need the `total` count, not the rows.
  const contacts = useListContactsQuery({ limit: 1 });
  const prospects = useListProspectsQuery({ limit: 1 });
  const users = useListUsersQuery({ limit: 1 });
  const subscription = useGetSubscriptionQuery();
  const tenant = useGetMyTenantQuery();

  const [dismissed, setDismissed] = useState<boolean>(() => {
    if (!tenantId) return false;
    return localStorage.getItem(dismissKey(tenantId)) === '1';
  });

  // Re-read dismissal when the tenant changes (login/switch).
  useEffect(() => {
    if (!tenantId) {
      setDismissed(false);
      return;
    }
    setDismissed(localStorage.getItem(dismissKey(tenantId)) === '1');
  }, [tenantId]);

  const dismiss = useCallback(() => {
    if (tenantId) localStorage.setItem(dismissKey(tenantId), '1');
    setDismissed(true);
  }, [tenantId]);

  const isLoading =
    contacts.isLoading ||
    prospects.isLoading ||
    users.isLoading ||
    subscription.isLoading ||
    tenant.isLoading;

  const contactsCount = contacts.data?.total ?? 0;
  const prospectsCount = prospects.data?.total ?? 0;
  const usersCount = users.data?.total ?? 0;
  const orgComplete = Boolean(tenant.data?.city && tenant.data?.phone);
  const subscribed =
    subscription.data?.status === SubscriptionStatus.Active ||
    subscription.data?.status === SubscriptionStatus.Trialing;

  const steps: ChecklistStep[] = [
    {
      id: 'contact',
      icon: Contact,
      title: 'Add your first contact',
      description: 'Start your book of business with a person you work with.',
      to: '/contacts',
      ctaLabel: 'Add a contact',
      done: contactsCount > 0,
    },
    {
      id: 'prospect',
      icon: UserPlus,
      title: 'Create a prospect',
      description: 'Track a lead through your pipeline to close.',
      to: '/prospects',
      ctaLabel: 'Add a prospect',
      done: prospectsCount > 0,
    },
    {
      id: 'org',
      icon: Building2,
      title: 'Complete your organization profile',
      description: 'Add your city and phone so records and documents are branded.',
      to: '/settings',
      ctaLabel: 'Edit profile',
      done: orgComplete,
    },
    {
      id: 'teammate',
      icon: Users,
      title: 'Invite a teammate',
      description: 'Bring a colleague in so work does not live in one head.',
      to: '/users',
      ctaLabel: 'Invite a teammate',
      done: usersCount > 1,
    },
    {
      id: 'subscription',
      icon: CreditCard,
      title: 'Choose your plan',
      description: 'Unlock the full workspace with an active subscription.',
      to: '/billing',
      ctaLabel: 'View plans',
      done: subscribed,
    },
  ];

  const total = steps.length;
  const completed = steps.filter((s) => s.done).length;
  const progress = total === 0 ? 0 : Math.round((completed / total) * 100);
  const isComplete = completed === total;

  // Track whether the tenant was ever seen with an open step this session, so
  // reaching 100% shows a celebration once rather than a checklist that never
  // appeared. Reset when data is still loading so we do not celebrate on mount.
  const wasIncompleteRef = useRef(false);
  if (!isLoading && !isComplete) wasIncompleteRef.current = true;
  const justCompleted =
    !dismissed && !isLoading && isComplete && wasIncompleteRef.current;

  // Show the checklist while data has loaded, the tenant has open steps, and it
  // has not been dismissed — or briefly to celebrate the final step (see
  // justCompleted). A fully complete checklist otherwise hides itself.
  const isVisible = (!dismissed && !isLoading && !isComplete) || justCompleted;

  return {
    steps,
    completed,
    total,
    progress,
    isComplete,
    isLoading,
    isVisible,
    justCompleted,
    dismiss,
  };
}
