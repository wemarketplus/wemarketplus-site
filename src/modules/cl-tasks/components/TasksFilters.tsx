import { Checkbox, Select, SearchInput } from '@/shared/ui/core';
import { STATUS_OPTIONS } from '../constants/tasksConstants';

interface TasksFiltersProps {
  search: string;
  status: string;
  mineOnly: boolean;
  onSearch: (value: string) => void;
  onStatus: (value: string) => void;
  onMineOnly: (value: boolean) => void;
}

// Search box + status select for the task list. Both are applied client-side
// (the /cl/tasks backend list is plain pagination with no filter params).
export function TasksFilters({
  search,
  status,
  mineOnly,
  onSearch,
  onStatus,
  onMineOnly,
}: TasksFiltersProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <SearchInput
        wrapperClassName="sm:max-w-sm sm:flex-1"
        value={search}
        onChange={onSearch}
        placeholder="Search tasks…"
        aria-label="Search tasks"
      />
      <Select
        value={status}
        onChange={(e) => onStatus(e.target.value)}
        aria-label="Filter by status"
        className="sm:w-48"
      >
        <option value="">All statuses</option>
        {STATUS_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
      {/* "Anything else assigned to you" — the guide's words for every role that
          ends on this screen. A toggle rather than a staff picker: this list is
          the reader's own to-do list, and filtering it by a COLLEAGUE is a
          management question that belongs on a management screen. */}
      <label className="inline-flex cursor-pointer items-center gap-2 text-[13px] text-foreground">
        <Checkbox
          checked={mineOnly}
          onChange={(e) => onMineOnly(e.target.checked)}
        />
        Assigned to me
      </label>
    </div>
  );
}
