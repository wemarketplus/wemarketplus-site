import { Search } from 'lucide-react';
import { Input } from '@/shared/ui/core';

interface TerritoriesFiltersProps {
  // Client-side search across name/city/state (the backend list is unfiltered).
  search: string;
  onSearch: (value: string) => void;
}

export function TerritoriesFilters({ search, onSearch }: TerritoriesFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <div className="relative max-w-sm flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by name, city, or state…"
          className="pl-9"
        />
      </div>
    </div>
  );
}
