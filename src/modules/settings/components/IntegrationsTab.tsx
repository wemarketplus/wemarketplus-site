import { toast } from 'sonner';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { INTEGRATIONS } from '../constants/settingsConstants';

export function IntegrationsTab() {
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
            const connected = i.status === 'connected';
            return (
              <li
                key={i.id}
                className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-4 py-4"
              >
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
                  <Icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-foreground">{i.name}</p>
                    <span
                      className={
                        connected
                          ? 'rounded-pill bg-success/15 px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-success'
                          : 'rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-muted-soft'
                      }
                    >
                      {connected ? 'Connected' : 'Available'}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-muted">{i.description}</p>
                  <div className="mt-3">
                    <Button
                      size="sm"
                      variant={connected ? 'secondary' : 'primary'}
                      onClick={() =>
                        toast.message(
                          connected
                            ? `${i.name} — manage flow not wired yet`
                            : `${i.name} — connect flow pending backend OAuth`,
                        )
                      }
                    >
                      {connected ? 'Manage' : 'Connect'}
                    </Button>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}
