import { optOrNull } from '@/shared/ui/entity';
import type { CreateContactRequest, UpdateContactRequest } from '../types/contactsTypes';
import type { ContactFormValues } from '../schema/contactSchema';
import type { ContactRecord } from '../types/contactsTypes';
import {
  CONTACT_RECORD_TYPE_LABELS,
  type ContactRecordType,
} from '../constants/contactsConstants';

// Form values -> POST /contacts body. Every optional here maps to a `nullable:
// true` column (contact.entity.ts — only `name` is NOT NULL), so all of them go as
// explicit nulls when blank: an omitted key in the PATCH means "leave unchanged",
// which used to make clearing a field in the edit form silently revert it.
export function toCreateContact(values: ContactFormValues): CreateContactRequest {
  return {
    name: values.name.trim(),
    ...optOrNull('title', values.title),
    ...optOrNull('email', values.email),
    ...optOrNull('phone', values.phone),
    // The polymorphic pair travels together — clearing the type clears the record.
    ...optOrNull('recordType', values.recordType),
    ...optOrNull('recordId', values.recordId),
    ...optOrNull('notes', values.notes),
  };
}

// PATCH body is the same shape (partial); the backend accepts any subset.
export function toUpdateContact(values: ContactFormValues): UpdateContactRequest {
  return toCreateContact(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toContactFormValues(contact: ContactRecord): ContactFormValues {
  return {
    name: contact.name,
    title: contact.title ?? '',
    email: contact.email ?? '',
    phone: contact.phone ?? '',
    recordType: contact.recordType ?? '',
    recordId: contact.recordId ?? '',
    notes: contact.notes ?? '',
  };
}

// "Attached to" display. The stored value is a machine string
// (`funding_opportunity`), so it needs its label; an unrecognised one is shown raw
// rather than hidden, so a value from outside CONTACT_RECORD_TYPE stays visible.
export function formatRecordType(recordType: string | null): string {
  if (!recordType) return '—';
  return CONTACT_RECORD_TYPE_LABELS[recordType as ContactRecordType] ?? recordType;
}
