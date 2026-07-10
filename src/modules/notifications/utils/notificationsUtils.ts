import type { AppNotification } from '@/shared/types';
import type { NotificationRecord } from '../types/notificationsTypes';

// The backend NotificationResponseDto and the UI's AppNotification differ: map
// the persisted shape (type/readAt/...) onto the display shape the drawer + bell
// expect (category/read/...).
function mapCategory(type: string): AppNotification['category'] {
  const t = type.toLowerCase();
  if (t.includes('task')) return 'task';
  if (t.includes('mention') || t.includes('message') || t.includes('chat')) return 'mention';
  if (t.includes('alert') || t.includes('warning') || t.includes('overdue')) return 'alert';
  return 'system';
}

export function mapNotification(n: NotificationRecord): AppNotification {
  return {
    id: n.id,
    category: mapCategory(n.type),
    title: n.title,
    body: n.body ?? '',
    createdAt: n.createdAt,
    read: n.readAt !== null,
  };
}
