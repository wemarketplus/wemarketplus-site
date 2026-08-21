import { SearchInput } from '@/shared/ui/core';

interface TerritoriesFiltersProps {
  // Client-side search across name/city/state (the backend list is unfiltered).
  search: string;
  onSearch: (value: string) => void;
}

export function TerritoriesFilters({ search, onSearch }: TerritoriesFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <SearchInput
        wrapperClassName="max-w-sm flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search by name, city, or state…"
      />
    </div>
  );
}
