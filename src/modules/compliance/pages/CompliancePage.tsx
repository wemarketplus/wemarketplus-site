import { Download, Search } from 'lucide-react';
import { Button, Card, CardContent, Input } from '@/shared/ui/core';
import { PortalShell } from '../components/PortalShell';
import { AuditLogTable } from '../components/AuditLogTable';
import { useAuditLog } from '../hooks/useAuditLog';
import { useCompliancePage } from '../hooks/useCompliancePage';

// Audit Log screen of the Compliance Portal (the portal's default landing is
// HIPAA Readiness; this is the /compliance/audit screen).
export function CompliancePage() {
  const { query, setQuery, onExport } = useCompliancePage();
  const { entries, total } = useAuditLog();

  return (
    <PortalShell
      title="HIPAA Audit Log"
      description="Immutable record of all PHI access and admin actions."
    >
      <Card dense>
        <CardContent className="flex flex-col gap-3 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative max-w-sm flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search the audit log…"
              className="pl-9"
            />
          </div>
          <Button
            variant="secondary"
            onClick={onExport}
          >
            <Download className="h-4 w-4" /> Export {total} entries
          </Button>
        </CardContent>
      </Card>

      <div className="mt-4">
        <AuditLogTable entries={entries} />
      </div>
    </PortalShell>
  );
}
