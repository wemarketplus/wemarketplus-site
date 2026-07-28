import { useRole } from '@/shared/rbac';
import { cn } from '@/shared/utils/cn';
import { OPERATIONS_VIEWS } from '../constants/clOperationsConstants';
import type { ClOperationsUiState } from '../types/clOperationsTypes';

interface OperationsViewNavProps {
  view: ClOperationsUiState['view'];
  onViewChange: (view: ClOperationsUiState['view']) => void;
}

export function OperationsViewNav({ view, onViewChange }: OperationsViewNavProps) {
  const { isAny } = useRole();
  const visibleViews = OPERATIONS_VIEWS.filter((v) => isAny(v.allow));

  return (
    <nav className="flex flex-wrap gap-1.5">
      {visibleViews.map((v) => (
        <button
          key={v.value}
          type="button"
          onClick={() => onViewChange(v.value)}
          className={cn(
            'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
            view === v.value
              ? 'border-primary/40 bg-primary/15 text-primary'
              : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
          )}
        >
          {v.label}
        </button>
      ))}
    </nav>
  );
}
