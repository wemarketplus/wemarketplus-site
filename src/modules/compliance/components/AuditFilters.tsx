import { X } from 'lucide-react';
import { Button, Input, Label } from '@/shared/ui/core';
import type { AuditLogFilters } from '../types/complianceTypes';

interface AuditFiltersProps {
  filters: AuditLogFilters;
  onChange: (key: keyof AuditLogFilters, value: string) => void;
  onClear: () => void;
}

// Structured, server-side audit filters: action, resource, actor (user id) and
// an inclusive date range. Each change resets pagination to page 1 (handled in
// the slice). Values are debounced only for the free-text search elsewhere;
// these fields fire on change since they map to exact/range backend filters.
export function AuditFilters({ filters, onChange, onClear }: AuditFiltersProps) {
  const hasActive = Object.values(filters).some((v) => v !== '');

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
      <div>
        <Label htmlFor="audit-action">Action</Label>
        <Input
          id="audit-action"
          value={filters.action}
          onChange={(e) => onChange('action', e.target.value)}
          placeholder="e.g. EXPORT"
        />
      </div>
      <div>
        <Label htmlFor="audit-resource">Resource</Label>
        <Input
          id="audit-resource"
          value={filters.resource}
          onChange={(e) => onChange('resource', e.target.value)}
          placeholder="e.g. prospect"
        />
      </div>
      <div>
        <Label htmlFor="audit-user">Actor (user id)</Label>
        <Input
          id="audit-user"
          value={filters.userId}
          onChange={(e) => onChange('userId', e.target.value)}
          placeholder="UUID"
        />
      </div>
      <div>
        <Label htmlFor="audit-from">From</Label>
        <Input
          id="audit-from"
          type="date"
          value={filters.dateFrom}
          onChange={(e) => onChange('dateFrom', e.target.value)}
        />
      </div>
      <div>
        <Label htmlFor="audit-to">To</Label>
        <Input
          id="audit-to"
          type="date"
          value={filters.dateTo}
          onChange={(e) => onChange('dateTo', e.target.value)}
        />
      </div>
      {hasActive && (
        <div className="sm:col-span-2 lg:col-span-5">
          <Button variant="ghost" size="sm" onClick={onClear}>
            <X className="h-3.5 w-3.5" /> Clear filters
          </Button>
        </div>
      )}
    </div>
  );
}
