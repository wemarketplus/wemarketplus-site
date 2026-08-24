import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { cn } from '@/shared/utils/cn';
import { CATEGORIES } from '../constants/integrationsConstants';
import { IntegrationTileCard } from '../components/IntegrationTileCard';
import { useIntegrations } from '../hooks/useIntegrations';
import { useIntegrationsPage } from '../hooks/useIntegrationsPage';

export function IntegrationsPage() {
  const { category, setCategory } = useIntegrationsPage();
  const { integrations, total } = useIntegrations();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className={PAGE_TITLE}>Integrations</h1>
        <p className="text-sm text-muted">
          {total} ways to extend your CRM — pick one to get started.
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5">
        {CATEGORIES.map((c) => (
          <button
            key={c.value}
            type="button"
            onClick={() => setCategory(c.value)}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
              category === c.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            )}
          >
            {c.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {integrations.map((tile) => (
          <IntegrationTileCard key={tile.id} tile={tile} />
        ))}
      </div>
    </div>
  );
}
