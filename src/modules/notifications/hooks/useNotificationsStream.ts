import { useEffect, useRef } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { notificationsApi } from '../api/notificationsApi';
import { NOTIFICATIONS_TAGS } from '../constants/notificationsConstants';
import type { NotificationRecord } from '../types/notificationsTypes';

const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

// Reconnect backoff (ms): grows on repeated failures, capped, and resets once a
// connection opens successfully.
const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

interface StreamEnvelope {
  type: 'notification' | 'ping';
  data?: NotificationRecord;
}

/**
 * Subscribes to the backend SSE feed (GET /notifications/stream) for the
 * authenticated user. EventSource cannot send an Authorization header, so the
 * access token rides as an `?access_token=` query param (the backend JWT
 * strategy accepts it on this route). On each new notification we prepend it to
 * the cached list and invalidate the List tag so the drawer, page, and unread
 * badge all refresh. Reconnects with capped backoff when the connection drops.
 *
 * Mount ONCE at the app shell. Single backend instance only — see
 * NotificationsStreamService on the backend.
 */
export function useNotificationsStream(): void {
  const dispatch = useAppDispatch();
  const token = useAppSelector((s) => s.auth?.token ?? null);
  const reconnectRef = useRef(RECONNECT_MIN_MS);

  useEffect(() => {
    if (!token) return;

    let source: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const handleNotification = (record: NotificationRecord) => {
      // Prepend into the default (paramless) list cache for an instant update.
      dispatch(
        notificationsApi.util.updateQueryData('listNotifications', undefined, (draft) => {
          if (draft.data.some((n) => n.id === record.id)) return;
          draft.data.unshift(record);
          draft.total += 1;
        }),
      );
      // Invalidate so any other list variants + the unread-count refetch from
      // the server (authoritative badge count).
      dispatch(notificationsApi.util.invalidateTags([NOTIFICATIONS_TAGS.List]));
    };

    const connect = () => {
      if (closed) return;
      const url = `${apiBase()}/notifications/stream?access_token=${encodeURIComponent(token)}`;
      source = new EventSource(url);

      source.onopen = () => {
        reconnectRef.current = RECONNECT_MIN_MS;
      };

      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data as string) as StreamEnvelope;
          if (payload.type === 'notification' && payload.data) {
            handleNotification(payload.data);
          }
          // 'ping' heartbeats are ignored; they only keep the socket alive.
        } catch {
          // Ignore malformed frames rather than tearing down the stream.
        }
      };

      source.onerror = () => {
        source?.close();
        source = null;
        if (closed) return;
        const delay = reconnectRef.current;
        reconnectRef.current = Math.min(delay * 2, RECONNECT_MAX_MS);
        retryTimer = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      source?.close();
    };
  }, [dispatch, token]);
}
