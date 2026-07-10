import { Input, Label, Select } from '@/shared/ui/core';
import {
  DOCUMENT_PARENT_LABELS,
  DOCUMENT_SCOPE_OPTIONS,
  type DocumentScope,
} from '../constants/documentsConstants';

interface DocumentsScopePickerProps {
  scope: DocumentScope;
  onScope: (value: DocumentScope) => void;
  parentId: string;
  onParentId: (value: string) => void;
  // True when parentId is a valid UUID (drives the inline hint).
  validParent: boolean;
}

// Documents are parent-scoped on the backend (employer=company / wib=WIB), and the
// list/create calls require the parent id. This picker collects both before the
// list loads.
export function DocumentsScopePicker({
  scope,
  onScope,
  parentId,
  onParentId,
  validParent,
}: DocumentsScopePickerProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
      <div className="flex flex-col gap-1">
        <Label htmlFor="doc-scope">Scope</Label>
        <Select
          id="doc-scope"
          value={scope}
          onChange={(e) => onScope(e.target.value as DocumentScope)}
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
        <Input
          id="doc-parent"
          value={parentId}
          onChange={(e) => onParentId(e.target.value)}
          placeholder="00000000-0000-0000-0000-000000000000"
        />
        {parentId.trim() && !validParent && (
          <p className="text-[12px] text-destructive">Enter a valid UUID to load documents.</p>
        )}
      </div>
    </div>
  );
}
