import { SECTION_TITLE } from '@/shared/ui/core/typography';
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
  /**
   * Confirmation-scale chrome: no close (×), no header/footer rules, and the
   * three blocks share one padding box instead of each owning a full one.
   *
   * The default chrome is sized for a FORM — a 28px close button and two
   * dividers, which for a two-line confirm produced a 61px header band holding
   * a 20px title and a ~40px gap between that title and the body ("unnecessary
   * empty space at the top of the popup"). The × is also redundant there: a
   * confirm always renders an explicit Cancel, and Escape/backdrop still close.
   */
  compact?: boolean;
}

// Mirrors the wemarketplus-site demo modals: dark blurred backdrop + a
// #0d1b31 panel with a titled header and a close (×). Closes on Escape /
// backdrop click. Used by every CommunityLink create form.
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  size = 'md',
  compact = false,
}: ModalProps) {
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
          'animate-slide-up relative z-10 w-full rounded-card border border-border/[0.1] bg-surface shadow-2xl',
          width,
        )}
      >
        <header
          className={cn(
            'flex items-center justify-between px-6',
            compact ? 'pt-5' : 'border-b border-border/[0.07] py-4',
          )}
        >
          <h2 className={SECTION_TITLE}>{title}</h2>
          {!compact && (
            <button
              type="button"
              aria-label="Close"
              onClick={onClose}
              className="flex h-7 w-7 items-center justify-center rounded-full text-muted hover:bg-foreground/[0.06] hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </header>
        <div
          className={cn(
            'max-h-[70vh] overflow-y-auto px-6',
            compact ? 'pb-1 pt-2' : 'py-5',
          )}
        >
          {children}
        </div>
        {footer && (
          <footer
            className={cn(
              'flex items-center justify-end gap-2 px-6',
              compact ? 'pb-5 pt-4' : 'border-t border-border/[0.07] py-4',
            )}
          >
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
