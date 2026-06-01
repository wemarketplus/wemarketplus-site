import { toast } from 'sonner';
import { Button, Card, CardContent } from '@/shared/ui/core';
import type { IntegrationTile } from '../types/integrationsTypes';
import { STATUS_TONE } from '../utils/integrationsUtils';

export function IntegrationTileCard({ tile }: { tile: IntegrationTile }) {
  const Icon = tile.icon;
  return (
    <Card>
      <CardContent className="space-y-4 px-5 py-5">
        <div className="flex items-start justify-between">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
            <Icon className="h-4 w-4" />
          </div>
          <span
            className={`rounded-pill border px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] ${STATUS_TONE[tile.status]}`}
          >
            {tile.status}
          </span>
        </div>
        <div>
          <h2 className="text-sm font-semibold text-foreground">{tile.name}</h2>
          <p className="mt-1 text-sm text-muted">{tile.description}</p>
        </div>
        <Button
          size="sm"
          variant={tile.status === 'connected' ? 'secondary' : 'primary'}
          onClick={() =>
            toast.message(
              tile.status === 'connected'
                ? `${tile.name} — manage flow not wired yet`
                : `${tile.name} — connect flow pending backend OAuth`,
            )
          }
        >
          {tile.status === 'connected' ? 'Manage' : 'Connect'}
        </Button>
      </CardContent>
    </Card>
  );
}
