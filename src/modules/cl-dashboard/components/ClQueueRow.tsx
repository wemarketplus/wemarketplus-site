import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

interface ClQueueRowProps {
  /** The screen where this item can actually be updated. */
  to: string;
  title: string;
  /** Secondary line — unit, due date, reporter. Empty string renders nothing. */
  detail?: string;
  /** Status/priority pills, right-aligned. */
  pills: ReactNode;
}

/**
 * One row in a CommunityLink work queue: what the work is, and what state it is
 * in. The whole row is the link — a field user tapping this on a phone should not
 * have to hit a small chevron.
 */
export function ClQueueRow({ to, title, detail, pills }: ClQueueRowProps) {
  return (
    <Link
      to={to}
      className="flex flex-wrap items-center gap-3 border-b border-border/[0.06] px-6 py-3 transition-colors last:border-b-0 hover:bg-foreground/[0.03]"
    >
      <div className="min-w-0 flex-1">
        <p className="truncate text-[13px] font-semibold text-foreground">
          {title}
        </p>
        {detail && <p className="truncate text-[11px] text-muted-soft">{detail}</p>}
      </div>
      <div className="flex shrink-0 items-center gap-1.5">{pills}</div>
    </Link>
  );
}
