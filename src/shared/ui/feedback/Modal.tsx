import { useEffect, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/shared/utils/cn';
import { useRegisterOverlay } from './overlayPresence';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  // Width preset for the panel.
  size?: 'sm' | 'md' | 'lg';
}

// Mirrors the wemarketplus-site demo modals: dark blurred backdrop + a
// #0d1b31 panel with a titled header and a close (×). Closes on Escape /
// backdrop click. Used by every CommunityLink create form.
export function Modal({ open, onClose, title, children, footer, size = 'md' }: ModalProps) {
  // Hides the app topbar for as long as this is open. Registered here rather than
  // in each caller because every form popup in the app — ConfirmDialog,
  // EntityFormModal, the entity drawers, and ~30 module modals — is this component.
  useRegisterOverlay(open);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const width = { sm: 'max-w-md', md: 'max-w-lg', lg: 'max-w-2xl' }[size];

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="fixed inset-0 bg-black/70 backdrop-blur-sm"
      />
      <div
        role="dialog"
        aria-modal="true"
        className={cn(
          'animate-slide-up relative z-10 w-full rounded-[14px] border border-border/[0.1] bg-surface shadow-2xl',
          width,
        )}
      >
        <header className="flex items-center justify-between border-b border-border/[0.07] px-6 py-4">
          <h2 className="text-[16px] font-extrabold text-foreground">{title}</h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="flex h-7 w-7 items-center justify-center rounded-full text-muted hover:bg-foreground/[0.06] hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="max-h-[70vh] overflow-y-auto px-6 py-5">{children}</div>
        {footer && (
          <footer className="flex items-center justify-end gap-2 border-t border-border/[0.07] px-6 py-4">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
