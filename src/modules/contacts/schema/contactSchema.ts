import { z } from 'zod';
import { CONTACT_RECORD_TYPE } from '../constants/contactsConstants';

const recordTypeValues = Object.values(CONTACT_RECORD_TYPE) as [
  string,
  ...string[],
];

// Create/edit contact form — mirrors CreateContactDto / UpdateContactDto
// (wemarketplus-backend/src/contacts/dto). Only `name` is required; the rest are
// optional and sent as explicit nulls when blank so clearing one really clears it.
// email is validated only when present (empty string clears through `.or('')`).
export const contactSchema = z
  .object({
    name: z.string().min(1, 'Name is required').max(255),
    title: z.string().max(255).optional(),
    email: z
      .string()
      .email('Enter a valid email')
      .max(255)
      .optional()
      .or(z.literal('')),
    phone: z.string().max(50).optional(),
    // Both halves of the polymorphic attachment come from pickers now, so the
    // rules describe the PAIR rather than the text a user typed: the type is one
    // of the known record types, the id is whatever that type's list offered.
    // The UUID rule stays as a backstop for the backend's @IsUUID, but it is now
    // trivially satisfied — the only thing that can be in there is an id the
    // picker put there. Blank stays legal on both: "not attached".
    recordType: z.enum(recordTypeValues).or(z.literal('')),
    recordId: z.string().uuid('Choose a record from the list').or(z.literal('')),
    notes: z.string().optional(),
  })
  // Half a pair is meaningless: an id with no type points at a row in an unknown
  // table, and a type with no id points at nothing. Both blank is fine — that is
  // how an attachment is cleared (clearing the type clears the record with it).
  .refine((values) => !values.recordType || Boolean(values.recordId), {
    message: 'Choose the record this contact belongs to, or clear the type',
    path: ['recordId'],
  });

export type ContactFormValues = z.infer<typeof contactSchema>;
