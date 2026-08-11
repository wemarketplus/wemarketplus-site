import { useAppSelector } from '@/app/hooks';
import { roleTitle } from '@/shared/rbac';
import { timeBasedGreeting } from '../utils/dashboardUtils';

export function useDashboardGreeting() {
  const user = useAppSelector((s) => s.auth.user);
  return {
    greeting: timeBasedGreeting(),
    name: user?.firstName ?? 'there',
    role: user?.role ?? null,
    /**
     * What to CALL them — the tenant's job title when they hold a custom role, else
     * their role label. Passed down instead of having the header look up ROLE_LABELS
     * itself, so "Signed in as …" agrees with the topbar and the sidebar footer
     * rather than calling a Volunteer Coordinator a Caregiver on one screen of three.
     */
    title: roleTitle(user?.role, user?.customRole?.name),
  };
}
