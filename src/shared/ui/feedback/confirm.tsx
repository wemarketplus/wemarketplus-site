import { useCallback, useState } from 'react';
import { ConfirmDialog, type ConfirmDialogProps } from './ConfirmDialog';

export type ConfirmRequest = Omit<
  ConfirmDialogProps,
  'open' | 'onConfirm' | 'onCancel' | 'isBusy'
>;

type Resolver = (request: ConfirmRequest) => Promise<boolean>;

/**
 * The mounted host's resolver. Module-level on purpose: `confirm()` is called from
 * plain hooks and async handlers that have no React context in scope, and threading
 * a dialog's props through 32 list pages would guarantee that one of them gets
 * missed — and a missed one deletes without asking, which is worse than the ugly
 * native dialog this replaces.
 */
let activeResolver: Resolver | null = null;

/**
 * Ask the user to confirm a destructive action. Resolves true only on explicit
 * confirmation.
 *
 * Replaces `window.confirm`. See ConfirmDialog for why the native one was wrong.
 *
 * FAILS CLOSED: if no <ConfirmHost/> is mounted, this resolves FALSE and warns
 * rather than assuming yes. A confirmation prompt that silently disappears must
 * cancel the action, never approve it.
 */
export async function confirm(request: ConfirmRequest): Promise<boolean> {
  if (!activeResolver) {
    console.error(
      '[confirm] No <ConfirmHost/> is mounted, so the action was cancelled. ' +
        'Mount ConfirmHost once near the app root.',
    );
    return false;
  }
  return activeResolver(request);
}

/**
 * Mount ONCE near the app root. Owns the dialog every `confirm()` call renders
 * into, so no page needs to know about it.
 */
export function ConfirmHost() {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const [resolve, setResolve] = useState<((ok: boolean) => void) | null>(null);

  const register = useCallback<Resolver>(
    (next) =>
      new Promise<boolean>((res) => {
        setRequest(next);
        // Stored in state as a thunk so React does not call it as an updater.
        setResolve(() => res);
      }),
    [],
  );

  // Registered during render rather than in an effect: a `confirm()` fired from an
  // event handler in the same tick as mount must still find a resolver.
  activeResolver = register;

  const settle = (ok: boolean) => {
    resolve?.(ok);
    setRequest(null);
    setResolve(null);
  };

  return (
    <ConfirmDialog
      open={request !== null}
      title={request?.title ?? ''}
      body={request?.body}
      confirmLabel={request?.confirmLabel ?? 'Confirm'}
      cancelLabel={request?.cancelLabel}
      destructive={request?.destructive}
      onConfirm={() => settle(true)}
      onCancel={() => settle(false)}
    />
  );
}
