import type { AppNotification } from '@/shared/types';

export type { AppNotification };

export interface NotificationsUiState {
  drawerOpen: boolean;
  filter: 'all' | 'unread' | AppNotification['category'];
}
