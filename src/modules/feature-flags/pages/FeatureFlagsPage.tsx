import { Flag, Loader2, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import { Switch } from '@/shared/ui';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useListAdminFeatureFlagsQuery,
  useUpdateFeatureFlagMutation,
} from '../api/featureFlagsApi';
import type { FeatureFlag } from '../types/featureFlagsApiTypes';
import { PAGE_TITLE } from '@/shared/ui/core/typography';

// SuperAdmin screen to manage runtime feature flags: list every flag and toggle
// its global default. Per-tenant overrides are shown read-only (a count) since
// the common operator action is flipping a flag on/off for everyone.
export function FeatureFlagsPage() {
  const { data, isLoading, isError, error, refetch } =
    useListAdminFeatureFlagsQuery();
  const [updateFlag, { isLoading: isSaving }] = useUpdateFeatureFlagMutation();

  const onToggleGlobal = async (flag: FeatureFlag) => {
    try {
      await updateFlag({ key: flag.key, enabled: !flag.enabledGlobally }).unwrap();
      toast.success(
        `${flag.key} is now ${!flag.enabledGlobally ? 'on' : 'off'} globally.`,
      );
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not update this flag.'));
    }
  };

  const flags = data ?? [];

  return (
    <div className="space-y-8">
      <header className="flex items-start gap-4">
        <div className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
          <Flag className="h-5 w-5" />
        </div>
        <div>
          <h1 className={PAGE_TITLE}>
            Feature flags
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted">
            Operator switches for gradual rollouts and kill-switches. Toggling a
            flag changes behaviour immediately, with no deploy. This is distinct
            from plan-tier gating (billing).
          </p>
        </div>
      </header>

      {isLoading && (
        <div className="flex items-center justify-center gap-2 rounded-lg border border-border/[0.08] py-16 text-sm text-muted">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading feature flags…
        </div>
      )}

      {isError && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-red-500/20 bg-red-500/[0.06] px-4 py-3 text-sm text-red-200">
          <span className="flex items-center gap-2">
            <TriangleAlert className="h-4 w-4" />
            {extractApiErrorMessage(error, 'Could not load feature flags.')}
          </span>
          <button
            type="button"
            onClick={() => refetch()}
            className="rounded-pill border border-border/20 px-3 py-1 text-xs font-semibold uppercase tracking-label text-foreground"
          >
            Retry
          </button>
        </div>
      )}

      {!isLoading && !isError && (
        <ul className="space-y-3">
          {flags.map((flag) => {
            const overrideCount = Object.keys(flag.overrides ?? {}).length;
            return (
              <li
                key={flag.key}
                className="flex items-center justify-between gap-4 rounded-lg border border-border/[0.08] bg-foreground/[0.02] px-4 py-4"
              >
                <div className="min-w-0">
                  <p className="font-mono text-sm text-foreground">{flag.key}</p>
                  <p className="mt-1 text-sm text-muted">{flag.description}</p>
                  {overrideCount > 0 && (
                    <p className="mt-1 text-xs text-muted-soft">
                      {overrideCount} tenant override{overrideCount === 1 ? '' : 's'}
                    </p>
                  )}
                </div>
                <Switch
                  checked={flag.enabledGlobally}
                  aria-label={`Toggle ${flag.key} globally`}
                  disabled={isSaving}
                  onCheckedChange={() => void onToggleGlobal(flag)}
                />
              </li>
            );
          })}
          {flags.length === 0 && (
            <li className="rounded-lg border border-border/[0.08] py-12 text-center text-sm text-muted">
              No feature flags defined yet.
            </li>
          )}
        </ul>
      )}
    </div>
  );
}
