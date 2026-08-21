import { SearchInput } from '@/shared/ui/core';

interface TrainingProvidersFiltersProps {
  // Server-side name search (backend GET /training-providers?search).
  search: string;
  onSearch: (value: string) => void;
}

export function TrainingProvidersFilters({ search, onSearch }: TrainingProvidersFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by provider name…"
      />
    </div>
  );
}
