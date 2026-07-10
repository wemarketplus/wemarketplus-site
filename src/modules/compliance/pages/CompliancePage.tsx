import { Download, RefreshCw, Search } from 'lucide-react';
import { Button, Card, CardContent, Input } from '@/shared/ui/core';
import { Alert } from '@/shared/ui/data-display';
import { EntityPagination } from '@/shared/ui/entity';
import { PortalShell } from '../components/PortalShell';
import { AuditFilters } from '../components/AuditFilters';
import { AuditLogTable } from '../components/AuditLogTable';
import { useAuditLog } from '../hooks/useAuditLog';
import { useCompliancePage } from '../hooks/useCompliancePage';

// Audit Log screen of the Compliance Portal: a live, filterable, paginated log
// viewer wired to GET /audit (read-only, admin/owner). Structured filters and
// pagination hit the server; the search box refines the current page.
export function CompliancePage() {
  const { query, setQuery, filters, setFilter, clearFilters, setPage, onExport, isExporting } =
    useCompliancePage();
  const { entries, total, page, pageCount, isFetching, isError, refetch } = useAuditLog();

  return (
    <PortalShell
      title="Audit Log"
      description="Immutable record of sensitive actions across your organization. Read only and tenant scoped."
    >
      <Card dense>
        <CardContent className="space-y-4 px-6 py-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative max-w-sm flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search this page…"
                className="pl-9"
              />
            </div>
            <Button variant="secondary" disabled={isExporting} onClick={() => void onExport()}>
              <Download className="h-4 w-4" />
              {isExporting ? 'Preparing…' : `Export ${total} entries`}
            </Button>
          </div>

          <AuditFilters filters={filters} onChange={setFilter} onClear={clearFilters} />
        </CardContent>
      </Card>

      {isError ? (
        <div className="mt-4 space-y-3">
          <Alert tone="r">
            Could not load the audit log. Your session may have expired or you may lack the
            audit_logs permission.
          </Alert>
          <Button variant="secondary" size="sm" onClick={() => void refetch()}>
            <RefreshCw className="h-4 w-4" /> Retry
          </Button>
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          <AuditLogTable
            entries={entries}
            loading={isFetching && entries.length === 0}
            empty={
              total === 0
                ? 'No audit activity has been recorded yet.'
                : 'No audit entries match your filters.'
            }
          />
          {pageCount > 1 && (
            <EntityPagination
              page={page}
              lastPage={pageCount}
              isFetching={isFetching}
              onPrev={() => setPage(page - 1)}
              onNext={() => setPage(page + 1)}
            />
          )}
        </div>
      )}
    </PortalShell>
  );
}
