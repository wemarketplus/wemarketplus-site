import { Select } from '@/shared/ui/core';
import { AGREEMENT_STATUS, AGREEMENT_STATUS_LABELS, type AgreementStatus } from '../constants/agreementsConstants';

interface AgreementsFiltersProps {
  // Server-side status filter (backend GET /agreements?status).
  status: AgreementStatus | '';
  onStatus: (value: AgreementStatus | '') => void;
}

export function AgreementsFilters({ status, onStatus }: AgreementsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value as AgreementStatus | '')}
        className="max-w-xs"
      >
        <option value="">All statuses</option>
        {Object.values(AGREEMENT_STATUS).map((v) => (
          <option key={v} value={v}>
            {AGREEMENT_STATUS_LABELS[v]}
          </option>
        ))}
      </Select>
    </div>
  );
}
