import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import { Search, X } from 'lucide-react';
import { cn } from '@/shared/utils/cn';
import { useGlobalSearch } from './useGlobalSearch';
import type { SearchResult } from './types';

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

// A modal command palette (Cmd/Ctrl+K). Runs client-side federated search over
// contacts, companies and prospects via useGlobalSearch, renders the results
// grouped by entity, and supports arrow-key navigation + Enter to open. Escape
// or a backdrop click closes it. Rendered once at the shell (DashboardHeader).
export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  const { active, minQuery, groups, flat, isLoading, hasResults } = useGlobalSearch(query, open);

  // Reset input + focus each time the palette opens.
  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      // Defer so the input exists before we focus it.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // Keep the highlighted row in range as results change.
  useEffect(() => {
    setActiveIndex((i) => (flat.length === 0 ? 0 : Math.min(i, flat.length - 1)));
  }, [flat.length]);

  // Map each flat result to its global index for highlight bookkeeping.
  const indexOf = useMemo(() => {
    const map = new Map<string, number>();
    flat.forEach((r, i) => map.set(resultKey(r), i));
    return map;
  }, [flat]);

  if (!open) return null;

  const go = (result: SearchResult) => {
    navigate(result.to);
    onClose();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (flat.length > 0) setActiveIndex((i) => (i + 1) % flat.length);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (flat.length > 0) setActiveIndex((i) => (i - 1 + flat.length) % flat.length);
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      const target = flat[activeIndex];
      if (target) go(target);
    }
  };

  // Rendered via a portal to document.body: the palette is mounted inside the
  // dashboard header, which uses backdrop-blur and therefore creates a stacking
  // context AND a containing block for fixed-position children — without the
  // portal, this "fixed inset-0" overlay is positioned relative to the 64px
  // header instead of the viewport, so the backdrop fails to cover the page
  // (content bleeds through) and clicks land on the wrong layer (page appears
  // frozen). Portaling to the body escapes that context entirely.
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-start justify-center p-4 pt-[12vh] sm:p-8 sm:pt-[14vh]">
      <button
        type="button"
        aria-label="Close search"
        onClick={onClose}
        className="fixed inset-0 bg-black/70 backdrop-blur-sm"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Global search"
        className="animate-slide-up relative z-10 w-full max-w-xl overflow-hidden rounded-card border border-border/[0.1] bg-surface shadow-2xl"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-3 border-b border-border/[0.07] px-4">
          <Search className="h-4 w-4 shrink-0 text-muted" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search contacts, companies, prospects…"
            className="h-12 flex-1 bg-transparent text-[14px] text-foreground placeholder:text-muted-soft focus:outline-none"
            aria-label="Search query"
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="flex h-6 w-6 items-center justify-center rounded-full text-muted hover:bg-foreground/[0.06] hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[52vh] overflow-y-auto py-2">
          {!active ? (
            <p className="px-4 py-6 text-center text-[13px] text-muted">
              Type at least {minQuery} characters to search.
            </p>
          ) : isLoading && !hasResults ? (
            <p className="px-4 py-6 text-center text-[13px] text-muted">Searching…</p>
          ) : !hasResults ? (
            /*
              The needle is NOT echoed back. It sat two lines above this one in
              the input the user is still looking at, so quoting it added nothing
              and cost plenty: a long or pasted term wrapped the panel, a stray
              paste rendered as a wall of quoted text, and any typed value —
              including one someone would not want on screen — was repeated in
              larger type than the field itself. What the state has to say is
              "nothing matched, here is what to try", and neither half needs the
              query in it. The second line names the three record types this
              palette actually searches, which is the fix for the most common
              cause of a miss: searching for something it never covered.
            */
            <div className="px-4 py-8 text-center">
              <p className="text-[13px] font-semibold text-foreground">
                No results found
              </p>
              <p className="mt-1 text-[12px] text-muted">
                Check the spelling, or try a shorter term — this searches
                contacts, companies and prospects.
              </p>
            </div>
          ) : (
            groups
              .filter((g) => g.results.length > 0)
              .map((group) => {
                const Icon = group.icon;
                return (
                  <div key={group.key} className="px-2 pb-1">
                    <p className="flex items-center gap-1.5 px-2 pb-1 pt-2 text-[10px] font-extrabold uppercase tracking-label text-muted-soft">
                      <Icon className="h-3 w-3" /> {group.label}
                    </p>
                    {group.results.map((result) => {
                      const idx = indexOf.get(resultKey(result)) ?? -1;
                      const isActive = idx === activeIndex;
                      return (
                        <button
                          key={resultKey(result)}
                          type="button"
                          onClick={() => go(result)}
                          onMouseMove={() => idx >= 0 && setActiveIndex(idx)}
                          className={cn(
                            'flex w-full flex-col items-start gap-0.5 rounded-md px-3 py-2 text-left',
                            isActive ? 'bg-primary/15' : 'hover:bg-foreground/[0.04]',
                          )}
                        >
                          <span className="text-[13px] font-semibold text-foreground">
                            {result.title}
                          </span>
                          {result.subtitle && (
                            <span className="text-[11px] text-muted">{result.subtitle}</span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                );
              })
          )}
        </div>

        <div className="flex items-center gap-3 border-t border-border/[0.07] px-4 py-2 text-[10px] text-muted-soft">
          <span>
            <kbd className="rounded bg-foreground/[0.06] px-1">↑</kbd>{' '}
            <kbd className="rounded bg-foreground/[0.06] px-1">↓</kbd> navigate
          </span>
          <span>
            <kbd className="rounded bg-foreground/[0.06] px-1">↵</kbd> open
          </span>
          <span>
            <kbd className="rounded bg-foreground/[0.06] px-1">esc</kbd> close
          </span>
        </div>
      </div>
    </div>,
    document.body,
  );
}

// Results across groups can share an entity id space only within a group, so
// key by group + id to stay unique in the flat list.
function resultKey(r: SearchResult): string {
  return `${r.group}:${r.id}`;
}
