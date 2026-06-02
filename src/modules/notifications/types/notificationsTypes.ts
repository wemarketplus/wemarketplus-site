import type { AppNotification } from '@/shared/types';

export type { AppNotification };

export type NotificationFilter = 'all' | 'unread' | AppNotification['category'];

export interface NotificationsUiState {
  drawerOpen: boolean;
  filter: NotificationFilter;
}
