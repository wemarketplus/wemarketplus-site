import { z } from 'zod';
import { COMPANY_STATUS } from '../constants/companiesConstants';

const STATUS_VALUES = Object.values(COMPANY_STATUS) as [string, ...string[]];

// Create/edit company form — mirrors CreateCompanyDto
// (wemarketplus-backend/src/companies/dto/create-company.dto.ts). Only
// `companyName` is required. website must be a URL when present; employee count
// is a non-negative int. Blank optionals are stripped before sending.
export const companySchema = z.object({
  companyName: z.string().min(1, 'Company name is required').max(255),
  companyType: z.string().max(500).optional(),
  status: z.enum(STATUS_VALUES).optional(),
  industry: z.string().max(500).optional(),
  fein: z.string().max(100).optional(),
  naicsCode: z.string().max(100).optional(),
  domain: z.string().max(500).optional(),
  website: z
    .string()
    .url('Enter a valid URL (https://…)')
    .max(1000)
    .optional()
    .or(z.literal('')),
  // The form registers this with valueAsNumber, which yields NaN on empty
  // input; coerce NaN -> undefined so an omitted count validates as optional
  // rather than "not a number". Typed as number|undefined so the resolver's
  // inferred output matches the form values (avoids the RHF Resolver mismatch).
  employeeCountTotal: z
    .number({ error: 'Enter a number' })
    .int('Whole number only')
    .min(0, 'Cannot be negative')
    .optional()
    .or(z.nan().transform(() => undefined)),
  primaryContactName: z.string().max(500).optional(),
  primaryContactEmail: z
    .string()
    .email('Enter a valid email')
    .max(500)
    .optional()
    .or(z.literal('')),
  primaryContactPhone: z.string().max(50).optional(),
  trainingNeeds: z.string().optional(),
  notes: z.string().optional(),
});

export type CompanyFormValues = z.infer<typeof companySchema>;
