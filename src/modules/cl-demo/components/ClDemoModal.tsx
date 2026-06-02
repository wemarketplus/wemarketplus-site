import { useEffect } from 'react';

interface ClDemoModalProps {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
}

// Reproduces the reference .modal-bg / .modal-panel: centered overlay, amber
// hairline panel, ✕ close button, and Esc-to-close.
export function ClDemoModal({ open, onClose, children }: ClDemoModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/75"
      onClick={onClose}
    >
      <div
        className="relative max-h-[88vh] w-full max-w-[480px] overflow-y-auto rounded-[16px] border border-[#f59e0b]/20 bg-[#0d1b31] p-7"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="absolute right-3.5 top-3 cursor-pointer border-none bg-transparent text-[20px] leading-none text-[#6b7fa3]"
        >
          ✕
        </button>
        {children}
      </div>
    </div>
  );
}
