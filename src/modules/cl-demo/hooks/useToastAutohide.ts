// Clears the demo toast 3s after it appears — mirrors the reference T()'s
// setTimeout. Keyed on the toast nonce so an identical repeated message still
// re-arms the timer.
import { useEffect } from 'react';
import type { ToastState } from '../types/clDemoTypes';

export function useToastAutohide(toast: ToastState | null, hide: () => void): void {
  useEffect(() => {
    if (!toast) return;
    const id = window.setTimeout(hide, 3000);
    return () => window.clearTimeout(id);
  }, [toast?.nonce, toast, hide]);
}
