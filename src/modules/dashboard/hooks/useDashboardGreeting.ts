import { useAppSelector } from '@/app/hooks';
import { timeBasedGreeting } from '../utils/dashboardUtils';

export function useDashboardGreeting() {
  const user = useAppSelector((s) => s.auth.user);
  return {
    greeting: timeBasedGreeting(),
    name: user?.firstName ?? 'there',
    role: user?.role ?? null,
  };
}
