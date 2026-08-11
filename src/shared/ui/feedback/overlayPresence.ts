import { useEffect, useSyncExternalStore } from 'react';

/**
 * "Is any popup surface open right now?" — one boolean the whole shell can read.
 *
 * The app topbar must not be visible while a popup form is open. The topbar sits
 * in the layout, above <main>, while modals are rendered deep inside whatever page
 * opened them, so there is no parent either one can ask. A tiny external store is
 * the least invasive answer: overlays register themselves while mounted, and
 * DashboardHeader subscribes.
 *
 * A COUNTER, not a boolean, because overlays legitimately stack — a ConfirmDialog
 * opened from inside a form modal, for instance. With a boolean the inner one
 * closing would reveal the topbar while the outer modal is still up.
 */
let openOverlays = 0;
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// Returns the derived boolean rather than the count: useSyncExternalStore compares
// snapshots with Object.is, so a stable primitive keeps subscribers from
// re-rendering when a second overlay opens on top of a first.
function getSnapshot() {
  return openOverlays > 0;
}

/** True while at least one popup (modal, dialog, drawer) is open. */
export function useOverlayOpen(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, () => false);
}

/**
 * Registers an overlay for as long as `open` is true. Call it unconditionally from
 * the overlay component — including above any `if (!open) return null`, so the
 * hook order never changes.
 */
export function useRegisterOverlay(open: boolean): void {
  useEffect(() => {
    if (!open) return;
    openOverlays += 1;
    listeners.forEach((l) => l());
    return () => {
      openOverlays -= 1;
      listeners.forEach((l) => l());
    };
  }, [open]);
}
