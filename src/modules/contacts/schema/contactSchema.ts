import { z } from 'zod';

// Create/edit contact form — mirrors CreateContactDto
// (wemarketplus-backend/src/contacts/dto/create-contact.dto.ts). Only `name` is
// required; the rest are optional and stripped when blank before sending.
// email is validated only when present (empty string clears through `.or('')`).
export const contactSchema = z.object({
  name: z.string().min(1, 'Name is required').max(255),
  title: z.string().max(255).optional(),
  email: z
    .string()
    .email('Enter a valid email')
    .max(255)
    .optional()
    .or(z.literal('')),
  phone: z.string().max(50).optional(),
  recordType: z.string().max(255).optional(),
  recordId: z
    .string()
    .uuid('Record id must be a valid UUID')
    .optional()
    .or(z.literal('')),
  notes: z.string().optional(),
});

export type ContactFormValues = z.infer<typeof contactSchema>;
