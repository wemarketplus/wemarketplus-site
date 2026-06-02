import { cn } from '@/shared/utils/cn';
import { FINANCIAL_VIEWS, HIGHLIGHT } from '../constants/clFinancialConstants';
import { useFinancialHistory } from '../hooks/useFinancialHistory';
import { useFinancialView } from '../hooks/useFinancialView';
import { FinancialTable } from '../components/FinancialTable';

export function ClFinancialPage() {
  const { view, setView } = useFinancialView();
  const { months, isUsingFixture } = useFinancialHistory();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Financial</h1>
        <p className="text-sm text-muted">
          Revenue ledger, leakage tracking, and concession approvals.
          {isUsingFixture && (
            <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
              Preview data
            </span>
          )}
        </p>
      </header>

      <nav className="flex flex-wrap gap-1.5">
        {FINANCIAL_VIEWS.map((v) => (
          <button
            key={v.value}
            type="button"
            onClick={() => setView(v.value)}
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

      <FinancialTable months={months} highlight={HIGHLIGHT[view]} />
    </div>
  );
}
