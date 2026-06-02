import type { OwnerScreenHeaderProps } from '../types/ownerPortalTypes';

// One-line header used at the top of every owner-portal screen so the layout
// stays consistent without each page hand-rolling its own.
export function OwnerScreenHeader({
  eyebrow,
  title,
  description,
  actions,
}: OwnerScreenHeaderProps) {
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="space-y-1">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
          {eyebrow}
        </p>
        <h1 className="font-display text-3xl leading-tight text-foreground">
          {title}
        </h1>
        {description && <p className="text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
