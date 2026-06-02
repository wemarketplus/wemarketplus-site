import { useAppSelector } from '@/app/hooks';

export function useActivityPage() {
  const activeTab = useAppSelector((s) => s.activity.activeTab);
  return { activeTab };
}
