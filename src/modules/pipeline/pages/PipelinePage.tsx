import { PipelineColumn } from '../components/PipelineColumn';
import { usePipelineColumns } from '../hooks/usePipelineColumns';

export function PipelinePage() {
  const { columns, total, isUsingFixture } = usePipelineColumns();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Pipeline</h1>
          <p className="text-sm text-muted">
            {total} prospects across {columns.length} stages
            {isUsingFixture && (
              <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                Preview data
              </span>
            )}
          </p>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        {columns.map((c) => (
          <PipelineColumn
            key={c.status}
            status={c.status}
            label={c.label}
            tone={c.tone}
            items={c.items}
          />
        ))}
      </div>
    </div>
  );
}
