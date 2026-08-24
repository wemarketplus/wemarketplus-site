import type { OwnerScreenHeaderProps } from '../types/ownerPortalTypes';
import { OVERLINE, PAGE_SUBTITLE, PAGE_TITLE } from '@/shared/ui/core/typography';

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
        <p className={OVERLINE}>{eyebrow}</p>
        <h1 className={PAGE_TITLE}>{title}</h1>
        {description && <p className={PAGE_SUBTITLE}>{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}
