import { cn } from '@/shared/utils/cn';
import { useClDemo } from '../hooks/useClDemo';
import { useToastAutohide } from '../hooks/useToastAutohide';

// Reproduces the reference #toast: bottom-right pill, amber border (red when
// error), auto-hides after 3s.
export function ClDemoToast() {
  const { toast, actions } = useClDemo();
  useToastAutohide(toast, actions.hideToast);

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
