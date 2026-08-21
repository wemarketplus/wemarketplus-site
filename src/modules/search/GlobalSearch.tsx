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
        // h-9 matches every other control in the topbar and the Button `sm`
        // size. The icon is 16px (h-4), the same as the bell and the sign-out
        // glyph beside it — it was 14px, which read as a lighter, smaller
        // control than its neighbours at the same nominal size.
        className="flex h-9 items-center gap-2 rounded-pill border border-border/[0.08] bg-surface/60 pl-3 pr-2 text-[12px] text-muted transition-colors hover:border-border/[0.16] hover:text-foreground"
      >
        <Search className="h-4 w-4 shrink-0" />
        <span className="hidden sm:inline">Search…</span>
        <kbd className="hidden items-center rounded bg-foreground/[0.06] px-1.5 py-0.5 text-[10px] leading-none text-muted-soft sm:inline-flex">
          {isMac ? '⌘' : 'Ctrl'} K
        </kbd>
      </button>
      <CommandPalette open={open} onClose={closePalette} />
    </>
  );
}
