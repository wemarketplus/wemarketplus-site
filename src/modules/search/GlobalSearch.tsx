import { Search } from 'lucide-react';
import { CommandPalette } from './CommandPalette';
import { useCommandPalette } from './useCommandPalette';

// Self-contained global-search entry point for the shell: a header trigger
// button, the Cmd/Ctrl+K shortcut, and the palette modal. DashboardHeader drops
// this in as a single element — no palette state to manage there.
export function GlobalSearch() {
  const { open, openPalette, closePalette } = useCommandPalette();
  const isMac =
    typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

  return (
    <>
      <button
        type="button"
        onClick={openPalette}
        aria-label="Search"
        className="flex items-center gap-2 rounded-pill border border-white/[0.08] bg-surface/60 py-1.5 pl-3 pr-2 text-[12px] text-muted transition-colors hover:border-white/[0.16] hover:text-foreground"
      >
        <Search className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Search…</span>
        <kbd className="hidden items-center rounded bg-white/[0.06] px-1.5 py-0.5 text-[10px] text-muted-soft sm:inline-flex">
          {isMac ? '⌘' : 'Ctrl'} K
        </kbd>
      </button>
      <CommandPalette open={open} onClose={closePalette} />
    </>
  );
}
