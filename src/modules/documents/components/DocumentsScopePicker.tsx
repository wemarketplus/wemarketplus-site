import { useCompanyLookup } from '@/shared/hooks';
import { Label, Select } from '@/shared/ui/core';

interface DocumentsScopePickerProps {
  parentId: string;
  onParentId: (value: string) => void;
}

/**
 * Documents are parent-scoped on the backend and the list/create calls require the
 * parent company's id, so this picker collects it before the list loads.
 *
 * History worth keeping: this was a free-text box with a `00000000-0000-…`
 * placeholder and an "enter a valid UUID" error, which made the whole Documents
 * page unreachable for anyone without database access. It also offered a second
 * "WIB" scope — a Grants-domain concept (Workforce Investment Board) with no
 * meaning in a hospice CRM — which is why the control is now a single company
 * picker rather than a scope switch.
 */
export function DocumentsScopePicker({
  parentId,
  onParentId,
}: DocumentsScopePickerProps) {
  const companies = useCompanyLookup(true);
  const isLoading = companies === undefined;
  const isEmpty = companies?.length === 0;

  return (
    <div className="flex flex-col gap-1">
      <Label htmlFor="doc-parent">Company</Label>
      <Select
        id="doc-parent"
        value={parentId}
        onChange={(e) => onParentId(e.target.value)}
        disabled={isLoading || isEmpty}
        className="max-w-[28rem]"
      >
        <option value="">
          {isLoading
            ? 'Loading…'
            : isEmpty
              ? 'No companies on file yet'
              : 'Select a company…'}
        </option>
        {(companies ?? []).map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </Select>
    </div>
  );
}
