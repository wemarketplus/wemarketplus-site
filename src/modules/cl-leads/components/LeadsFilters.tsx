import { Select, SearchInput } from '@/shared/ui/core';
import { STAGE_OPTIONS, URGENCY_OPTIONS } from '../constants/leadsConstants';

interface LeadsFiltersProps {
  search: string;
  stage: string;
  urgency: string;
  onSearch: (value: string) => void;
  onStage: (value: string) => void;
  onUrgency: (value: string) => void;
}

// Search box + stage + urgency selects for the lead pipeline. Matches the
// CommunityLink pipeline screen (search leads / All Stages / All Urgency).
export function LeadsFilters({
  search,
  stage,
  urgency,
  onSearch,
  onStage,
  onUrgency,
}: LeadsFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <SearchInput
        wrapperClassName="sm:max-w-sm sm:flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search leads…"
        aria-label="Search leads"
      />
      <Select
        value={stage}
        onChange={(e) => onStage(e.target.value)}
        aria-label="Filter by stage"
        className="sm:w-48"
      >
        <option value="">All stages</option>
        {STAGE_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
      <Select
        value={urgency}
        onChange={(e) => onUrgency(e.target.value)}
        aria-label="Filter by urgency"
        className="sm:w-40"
      >
        <option value="">All urgency</option>
        {URGENCY_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}
