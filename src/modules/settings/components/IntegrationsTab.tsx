import { Card, CardContent } from '@/shared/ui/core';
import { useGetDriveStatusQuery } from '@/modules/integrations/api/integrationsApi';
import type { SettingsIntegration } from '../types/settingsTypes';
import { DRIVE_INTEGRATION_ID, INTEGRATIONS } from '../constants/settingsConstants';

type BadgeTone = 'success' | 'muted' | 'pending';

interface TileStatus {
  label: string;
  tone: BadgeTone;
}

const BADGE_CLASSES: Record<BadgeTone, string> = {
  success:
    'rounded-pill bg-success/15 px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-success',
  muted:
    'rounded-pill bg-foreground/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-muted-soft',
  pending:
    'rounded-pill bg-foreground/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-muted animate-pulse',
};

export function IntegrationsTab() {
  // The one live, per-tenant status the backend exposes today.
  const {
    data: driveStatus,
    isLoading: driveLoading,
    isError: driveError,
  } = useGetDriveStatusQuery();

  const resolveStatus = (integration: SettingsIntegration): TileStatus => {
    if (integration.id === DRIVE_INTEGRATION_ID) {
      if (driveLoading) return { label: 'Checking…', tone: 'pending' };
      if (driveError) return { label: 'Status unavailable', tone: 'muted' };
      return driveStatus?.connected
        ? { label: 'Connected', tone: 'success' }
        : { label: 'Not connected', tone: 'muted' };
    }
    // Managed integrations have no per-tenant status endpoint — label honestly.
    return { label: 'Configured by administrator', tone: 'muted' };
  };

  return (
    <Card>
      <CardContent className="px-6 py-6">
        <header className="mb-6">
          <h2 className="text-base font-semibold text-foreground">Integrations</h2>
          <p className="mt-1 text-sm text-muted">
            Connect outside tools to power features inside the CRM.
          </p>
        </header>

        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {INTEGRATIONS.map((i) => {
            const Icon = i.icon;
            const status = resolveStatus(i);
            return (
              <li
                key={i.id}
                className="flex items-start gap-3 rounded-lg border border-border/[0.06] bg-foreground/[0.02] px-4 py-4"
              >
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
                  <Icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-foreground">{i.name}</p>
                    <span className={BADGE_CLASSES[status.tone]}>{status.label}</span>
                  </div>
                  <p className="mt-1 text-xs text-muted">{i.description}</p>
                </div>
              </li>
            );
          })}
        </ul>

        <p className="mt-5 text-xs text-muted-soft">
          Google Drive status is live. Other integrations are provisioned by your
          administrator and managed outside this screen.
        </p>
      </CardContent>
    </Card>
  );
}
