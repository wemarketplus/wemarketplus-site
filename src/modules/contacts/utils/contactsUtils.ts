import { opt } from '@/shared/ui/entity';
import type { CreateContactRequest, UpdateContactRequest } from '../types/contactsTypes';
import type { ContactFormValues } from '../schema/contactSchema';
import type { ContactRecord } from '../types/contactsTypes';

// Form values -> POST /contacts body. Drops blank optionals so we never send
// empty strings the DTO would reject (email/recordId are IsEmail/IsUUID gated).
export function toCreateContact(values: ContactFormValues): CreateContactRequest {
  return {
    name: values.name.trim(),
    ...opt('title', values.title),
    ...opt('email', values.email),
    ...opt('phone', values.phone),
    ...opt('recordType', values.recordType),
    ...opt('recordId', values.recordId),
    ...opt('notes', values.notes),
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
