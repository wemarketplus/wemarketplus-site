import { CATEGORY_LABEL, CATEGORY_ORDER } from '../constants/clReportsConstants';
import { ReportCard } from '../components/ReportCard';
import { useReportCatalog } from '../hooks/useReportCatalog';

export function ClReportsPage() {
  const { reports, grouped, isUsingFixture, isLoading, metricsById } = useReportCatalog();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Reports</h1>
        <p className="text-sm text-muted">
          {reports.length} reports
          {isLoading && (
            <span className="ml-2 text-[11px] text-muted-soft">· loading live data…</span>
          )}
          {isUsingFixture && (
            <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
              Preview data
            </span>
          )}
        </p>
      </header>

      {CATEGORY_ORDER.map((category) => {
        const items = grouped[category];
        if (!items || items.length === 0) return null;
        return (
          <section key={category} className="space-y-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-soft">
              {CATEGORY_LABEL[category]}
            </h2>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((r) => (
                <ReportCard key={r.id} report={r} live={metricsById.get(r.id)} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
