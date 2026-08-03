import { Label, Select } from '@/shared/ui/core';
import { useCompanyLookup, useWibLookup } from '@/shared/hooks';
import {
  DOCUMENT_PARENT_LABELS,
  DOCUMENT_SCOPE,
  DOCUMENT_SCOPE_OPTIONS,
  type DocumentScope,
} from '../constants/documentsConstants';

interface DocumentsScopePickerProps {
  scope: DocumentScope;
  onScope: (value: DocumentScope) => void;
  parentId: string;
  onParentId: (value: string) => void;
}

/**
 * Documents are parent-scoped on the backend (employer=company / wib=WIB) and the
 * list/create calls require that parent's id, so this picker collects both before
 * the list loads.
 *
 * The parent used to be a free-text box with a `00000000-0000-…` placeholder and an
 * "enter a valid UUID" error, which made the entire Documents page unreachable for
 * anyone without database access. It is now a DEPENDENT picker: the scope chooses
 * which list to offer, and the parent is selected from it by name.
 *
 * Both lists load rather than only the active one, so switching scope doesn't stall
 * a control the user is already using. They are capped at LOOKUP_PAGE_SIZE and
 * cached by RTK Query.
 */
export function DocumentsScopePicker({
  scope,
  onScope,
  parentId,
  onParentId,
}: DocumentsScopePickerProps) {
  const companies = useCompanyLookup(true);
  const wibs = useWibLookup(true);

  const options = scope === DOCUMENT_SCOPE.Employer ? companies : wibs;
  const isLoading = options === undefined;
  const isEmpty = options?.length === 0;
  const noun = DOCUMENT_PARENT_LABELS[scope].toLowerCase();

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
      <div className="flex flex-col gap-1">
        <Label htmlFor="doc-scope">Scope</Label>
        <Select
          id="doc-scope"
          value={scope}
          onChange={(e) => {
            // Changing scope invalidates the chosen parent — a company is not a
            // WIB, and silently keeping the old id would query the wrong parent.
            onParentId('');
            onScope(e.target.value as DocumentScope);
          }}
          className="max-w-[16rem]"
        >
          {DOCUMENT_SCOPE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      </div>
      <div className="flex flex-1 flex-col gap-1">
        <Label htmlFor="doc-parent">{DOCUMENT_PARENT_LABELS[scope]}</Label>
        <Select
          id="doc-parent"
          value={parentId}
          onChange={(e) => onParentId(e.target.value)}
          disabled={isLoading || isEmpty}
        >
          <option value="">
            {isLoading
              ? 'Loading…'
              : isEmpty
                ? `No ${noun} on file yet`
                : `Select a ${noun}…`}
          </option>
          {(options ?? []).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      </div>
    </div>
  );
}
