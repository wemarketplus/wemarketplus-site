import { Select } from '@/shared/ui/core';
import { APPLICATION_STATUS, APPLICATION_STATUS_LABELS, type ApplicationStatus } from '../constants/applicationsConstants';

interface ApplicationsFiltersProps {
  // Server-side status filter (backend GET /applications?status).
  status: ApplicationStatus | '';
  onStatus: (value: ApplicationStatus | '') => void;
}

export function ApplicationsFilters({ status, onStatus }: ApplicationsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value as ApplicationStatus | '')}
        className="max-w-xs"
      >
        <option value="">All statuses</option>
        {Object.values(APPLICATION_STATUS).map((v) => (
          <option key={v} value={v}>
            {APPLICATION_STATUS_LABELS[v]}
          </option>
        ))}
      </Select>
    </div>
  );
}
