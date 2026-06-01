import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import { IntegrationTileCard } from '../components/IntegrationTileCard';
import { useIntegrations } from '../hooks/useIntegrations';
import { setIntegrationCategory } from '../store/integrationsSlice';
import type { IntegrationsUiState } from '../types/integrationsTypes';

const CATEGORIES: ReadonlyArray<{
  value: IntegrationsUiState['category'];
  label: string;
}> = [
  { value: 'all', label: 'All' },
  { value: 'data', label: 'Data' },
  { value: 'communications', label: 'Comms' },
  { value: 'workflow', label: 'Workflow' },
  { value: 'analytics', label: 'Analytics' },
];

export function IntegrationsPage() {
  const dispatch = useAppDispatch();
  const category = useAppSelector((s) => s.integrations.category);
  const { integrations, total } = useIntegrations();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Integrations</h1>
        <p className="text-sm text-muted">
          {total} ways to extend your CRM — pick one to get started.
        </p>
      </header>

      <div className="flex flex-wrap gap-1.5">
        {CATEGORIES.map((c) => (
          <button
            key={c.value}
            type="button"
            onClick={() => dispatch(setIntegrationCategory(c.value))}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              category === c.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
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
