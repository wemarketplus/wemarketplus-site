import { z } from 'zod';
import { AGREEMENT_STATUS } from '../constants/agreementsConstants';

// Create/edit agreement form — mirrors CreateAgreementDto / UpdateAgreementDto
// (wemarketplus-backend/src/agreements/dto). The backend accepts either
// `agreementName` or `title` as the name (aliased in the service); we always send
// the canonical `agreementName`. `value` (aliased from `amount`) is the money
// field. Backend enforces a min length of 2 on named string fields.
const statusValues = Object.values(AGREEMENT_STATUS) as [string, ...string[]];

const optionalNonNegativeNumber = z
  .number()
  .min(0, 'Must be zero or more')
  .optional()
  .or(z.nan().transform(() => undefined));

// Optional strings the backend length-validates (min 2) only when present.
const optionalName = z
  .string()
  .min(2, 'Must be at least 2 characters')
  .max(255)
  .optional()
  .or(z.literal(''));

export const agreementSchema = z.object({
  agreementName: z.string().min(2, 'Agreement name is required').max(255),
  companyName: optionalName,
  counterparty: optionalName,
  agreementType: optionalName,
  status: z.enum(statusValues).optional().or(z.literal('')),
  value: optionalNonNegativeNumber,
  effectiveDate: z.string().optional(),
  expirationDate: z.string().optional(),
  notes: z.string().optional(),
});

export type AgreementFormValues = z.infer<typeof agreementSchema>;
