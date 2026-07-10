import { useCallback, useEffect, useState } from 'react';

// Owns the command-palette open state and binds the Cmd/Ctrl+K shortcut. Mount
// once at the shell (DashboardHeader) so the shortcut works from any page. The
// listener ignores the combo while typing in an input/textarea only when the
// palette is closed — Cmd+K should still open it from anywhere, so we always
// intercept the exact combo.
export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  const openPalette = useCallback(() => setOpen(true), []);
  const closePalette = useCallback(() => setOpen(false), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return { open, openPalette, closePalette };
}
