import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { ContactFormValues } from '../schema/contactSchema';

export const CONTACTS_PAGE_SIZE = 20;

/**
 * The records a contact may be attached to.
 *
 * A contact is POLYMORPHIC: it points at a record through the pair
 * (recordType, recordId). The column is plain varchar with no enum behind it, so
 * for a long time there was no list to drive a picker from and `recordId` stayed a
 * "paste the UUID" box no end user could fill. This constant IS that list — the
 * product answer to "which record types may a contact attach to?".
 *
 * Scoped to the three Grant-CRM records that (a) a contact person plausibly
 * belongs to and (b) the backend actually exposes as a tenant-scoped list
 * endpoint, which is what a picker needs: GET /companies, GET /funding,
 * GET /applications. They are also the three lists `shared/hooks` already
 * publishes a lookup for.
 *
 * Deliberately EXCLUDED: `wib` (Workforce Investment Board) — a Grants concept
 * with no meaning in this product, dropped from the Documents scope picker for the
 * same reason — and `user`, which is an operator of the app, not a record.
 *
 * The values are the strings stored in `contacts.recordType`, so they must not be
 * renamed casually; they follow the singular snake_case the app's other polymorphic
 * descriptors use (compliance alerts store "application" / "revenue_record").
 * Adding a type here means adding its lookup in useAttachableRecordLookup too.
 */
export const CONTACT_RECORD_TYPE = {
  Company: 'company',
  FundingOpportunity: 'funding_opportunity',
  Application: 'application',
} as const;

export type ContactRecordType =
  (typeof CONTACT_RECORD_TYPE)[keyof typeof CONTACT_RECORD_TYPE];

export const CONTACT_RECORD_TYPE_LABELS: Record<ContactRecordType, string> = {
  company: 'Company',
  funding_opportunity: 'Funding opportunity',
  application: 'Application',
};

// Blank first: a contact does not have to be attached to anything, and picking
// this back is how the pair is cleared (it clears `recordId` with it).
export const CONTACT_RECORD_TYPE_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Not attached' },
  ...Object.values(CONTACT_RECORD_TYPE).map((value) => ({
    value,
    label: CONTACT_RECORD_TYPE_LABELS[value],
  })),
];

// Field descriptors driving the create/edit modal (EntityFormModal). Order here
// is render order; `full` spans both grid columns.
//
// recordType/recordId are the polymorphic attachment, and they are a PAIR: the
// type names the list, the record is chosen from it (`dependsOn`). `recordId` was
// a free-text "Record id (UUID)" box that no end user could fill and that answered
// "Record id must be a valid UUID" to anything they typed. Choosing the type first
// is what gives the picker a list to show.
export const CONTACT_FIELDS: ReadonlyArray<EntityField<ContactFormValues>> = [
  { name: 'name', label: 'Name', full: true, placeholder: 'Jane Doe' },
  { name: 'title', label: 'Title', placeholder: 'Program Director' },
  { name: 'email', label: 'Email', type: 'email', placeholder: 'jane@example.org' },
  { name: 'phone', label: 'Phone', type: 'tel', placeholder: '(555) 123-4567' },
  {
    name: 'recordType',
    label: 'Record type',
    type: 'select',
    options: CONTACT_RECORD_TYPE_OPTIONS,
  },
  {
    name: 'recordId',
    label: 'Record',
    type: 'lookup',
    dependsOn: 'recordType',
    placeholder: 'Select a record…',
  },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
