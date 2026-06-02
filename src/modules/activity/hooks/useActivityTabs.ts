import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { setActivityTab } from '../store/activitySlice';
import type { ActivityUiState } from '../types/activityTypes';

export function useActivityTabs() {
  const dispatch = useAppDispatch();
  const activeTab = useAppSelector((s) => s.activity.activeTab);
  const setTab = (tab: ActivityUiState['activeTab']) =>
    dispatch(setActivityTab(tab));
  return { activeTab, setTab };
}
