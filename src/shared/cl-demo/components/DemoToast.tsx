import { cn } from '@/shared/utils/cn';
import { useToastAutohide } from '../hooks/useToastAutohide';
import type { ToastState } from '../types';

interface DemoToastProps {
  toast: ToastState | null;
  onHide: () => void;
}

// Reproduces the reference #toast: bottom-right pill, amber border (red when
// error), auto-hides after 3s. Presentational — the toast state + hide action
// are owned by each demo module's store and passed in.
export function DemoToast({ toast, onHide }: DemoToastProps) {
  useToastAutohide(toast, onHide);

  return (
    <div
      className={cn(
        'fixed bottom-5 right-5 z-[99999] rounded-[10px] border px-[18px] py-[11px] text-[13px] font-semibold text-[#f4f8ff] transition-all',
        toast
          ? 'translate-y-0 opacity-100'
          : 'pointer-events-none translate-y-2 opacity-0',
        toast?.error
          ? 'border-[#f87171]/40 bg-[#1a0d0d]'
          : 'border-[#f59e0b]/35 bg-[#0d1b31]',
      )}
      role="status"
      aria-live="polite"
    >
      {toast?.message}
    </div>
  );
}
