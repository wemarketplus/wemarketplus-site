import { toast } from 'sonner';
import type { IntegrationTile } from '../types/integrationsTypes';

export function useIntegrationTile(tile: IntegrationTile) {
  const onAction = () =>
    toast.message(
      tile.status === 'connected'
        ? `${tile.name} — manage flow not wired yet`
        : `${tile.name} — connect flow pending backend OAuth`,
    );
  return { onAction };
}
