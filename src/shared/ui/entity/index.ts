// Reusable "entity CRUD page" kit. A new list+create+edit+delete module is
// expressible as: 1 zod schema, 1 field array (EntityField[]), column defs, and
// two thin wiring files (form-to-DTO mapping + the page). See
// `modules/contacts` for the canonical template.
//
// A new module provides:
//   - a zod schema + inferred form-values type (create/edit form)
//   - an EntityField<FormValues>[] describing the inputs (drives EntityFormModal)
//   - DataTable Column<Entity>[] for the list (add an actions column with
//     EntityRowActions)
//   - a form-to-DTO mapper using `opt`/`optNum` to strip blank optionals
//   - a page that composes EntityListPage + EntityPagination + useEntityCrud +
//     usePaginatedList around the module's RTK Query hooks
export { EntityListPage } from './EntityListPage';
export { EntityPagination } from './EntityPagination';
export { EntityRowActions } from './EntityRowActions';
export { EntityFormModal } from './EntityFormModal';
export { usePaginatedList } from './usePaginatedList';
export { useEntityCrud } from './useEntityCrud';
// Opt-in bulk (multi-select) support: a selection hook, a sequential
// delete-per-id orchestrator, and the selection toolbar. Pages wire these
// together and pass a `selection` object to <DataTable/>. Fully additive —
// lists that don't use them behave exactly as before.
export { useBulkSelection, type BulkSelection } from './useBulkSelection';
export {
  useBulkDelete,
  type BulkDeleteController,
  type BulkDeleteProgress,
} from './useBulkDelete';
export { BulkActionBar } from './BulkActionBar';
export { opt, optNum } from './formValues';
export type {
  EntityField,
  EntityFieldType,
  EntitySelectOption,
  EntityFormModalProps,
} from './types';
