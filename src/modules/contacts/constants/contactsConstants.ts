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
 *
 * NOTE (2026-08-06): `funding_opportunity` and `application` are Grants-domain
 * records. The Grants domain is NOT NEEDED and PENDING REMOVAL, so both are now
 * hidden from the pickers — see CONTACT_RECORD_TYPE_OPTIONS below. They stay in
 * this map (and in the labels map) on purpose: the values are already persisted
 * in `contacts.recordType`, and both the zod enum in contactSchema and the table
 * label lookup read this map, so dropping the keys would break editing and
 * labelling any contact already attached to one. Purge the stored rows first.
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

// The record types a user may actually PICK — drives both the create/edit
// modal's recordType select and the Contacts list filter.
//
// Company only. The two Grants types (Funding opportunity / Application) are
// deliberately omitted: the Grants domain is NOT NEEDED and PENDING REMOVAL, and
// was hidden from the UI on 2026-08-06 per the product owner, so a user must not
// be able to attach a new contact to a Grants record or filter by one. Restore
// by listing them here again (they are still in CONTACT_RECORD_TYPE above, and
// useAttachableRecordLookup still resolves their lists).
//
// Blank first: a contact does not have to be attached to anything, and picking
// this back is how the pair is cleared (it clears `recordId` with it).
export const CONTACT_RECORD_TYPE_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Not attached' },
  ...[CONTACT_RECORD_TYPE.Company].map((value) => ({
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
