import type { ReactNode } from 'react';
import type { AppNotification, ID, ISODateString, PaginationParams } from '@/shared/types';

export type { AppNotification };

// Mirrors wemarketplus-backend/src/notifications/dto/notification-response.dto.ts.
export interface NotificationRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  type: string;
  title: string;
  body: string | null;
  relatedId: ID | null;
  readAt: ISODateString | null;
  respondedAt: ISODateString | null;
  responseAction: string | null;
  createdAt: ISODateString;
}

// GET /notifications query — extends pagination with unreadOnly filter.
export interface ListNotificationsQuery extends PaginationParams {
  unreadOnly?: boolean;
}

// POST /notifications/:id/respond body.
export interface RespondNotificationRequest {
  id: ID;
  action: string;
}

export interface UnreadCountResponse {
  count: number;
}

export type NotificationFilter = 'all' | 'unread' | AppNotification['category'];

export interface NotificationsUiState {
  drawerOpen: boolean;
  filter: NotificationFilter;
}

// --- Component prop types ---

export interface NotificationsListProps {
  items: readonly AppNotification[];
  emptyState?: ReactNode;
  // Called when a row is clicked (marks read / closes drawer). Owned by a hook.
  onActivate?: (notification: AppNotification) => void;
}
