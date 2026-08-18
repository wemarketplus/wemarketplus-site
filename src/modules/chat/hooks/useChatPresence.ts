import { useEffect, useRef, useState } from 'react';
import { useAppSelector } from '@/app/hooks';

const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

// Reconnect backoff (ms) — same shape as useNotificationsStream.
const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

interface PresenceEnvelope {
  type: 'presence';
  data?: { online?: string[]; ts?: number };
}

/**
 * Who in the tenant is online right now, from GET /chat/stream.
 *
 * WHY A STREAM FOR THIS AND A POLL FOR MESSAGES — the split looks backwards until
 * you read the backend. `ChatService.stream` emits ONLY a `presence` event carrying
 * the online user-id list, and its own comment says real-time message delivery is
 * left to the client. So the stream is the only place the ID LIST exists (the
 * heartbeat response carries a count and nothing else), and it is not a message
 * channel at all. Messages therefore poll and presence subscribes — each uses the
 * transport that actually carries it.
 *
 * Subscribing also keeps the caller marked online: every tick re-stamps the
 * subscriber's presence server-side, which is why an open screen does not need to
 * POST /chat/heartbeat as well.
 *
 * EventSource cannot set an Authorization header, so the token rides as
 * `?access_token=` — the JWT strategy accepts it as a fallback extractor
 * (auth/strategies/jwt.strategy.ts), the same mechanism the notifications stream
 * uses.
 *
 * Returns an empty set until the first tick arrives, and on a tenant below Gold —
 * where the feature guard rejects the connection — it stays empty and simply retries
 * with backoff. No presence dots is the correct render for "we do not know yet".
 */
export function useChatPresence(enabled: boolean): ReadonlySet<string> {
  const token = useAppSelector((s) => s.auth?.token ?? null);
  const [online, setOnline] = useState<ReadonlySet<string>>(() => new Set());
  const reconnectRef = useRef(RECONNECT_MIN_MS);

  useEffect(() => {
    if (!enabled || !token) return;

    let source: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      if (closed) return;
      const url = `${apiBase()}/chat/stream?access_token=${encodeURIComponent(token)}`;
      source = new EventSource(url);

      source.onopen = () => {
        reconnectRef.current = RECONNECT_MIN_MS;
      };

      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data as string) as PresenceEnvelope;
          if (payload.type === 'presence' && payload.data?.online) {
            setOnline(new Set(payload.data.online));
          }
        } catch {
          // Ignore a malformed frame rather than tearing down the stream.
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
  }, [enabled, token]);

  return online;
}
