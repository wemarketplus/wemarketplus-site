import { z } from 'zod';

// Create/edit contract form — mirrors CreateContractDto
// (wemarketplus-backend/src/contracts/dto/create-contract.dto.ts). companyName
// is required (1..200); the rest are optional and stripped when blank before
// sending. value inputs register with valueAsNumber, so a blank field yields
// NaN; accept NaN (validates as "unset") and let optNum drop it before send.
const optionalNonNegativeNumber = z
  .number()
  .min(0, 'Value cannot be negative')
  .optional()
  .or(z.nan().transform(() => undefined));

export const contractSchema = z.object({
  companyName: z.string().min(1, 'Company is required').max(200),
  contractType: z.string().max(200).optional(),
  value: optionalNonNegativeNumber,
  status: z
    .enum(['draft', 'active', 'signed', 'expired', 'terminated'])
    .optional()
    .or(z.literal('')),
  contractNumber: z.string().max(40).optional(),
  signedDate: z.string().optional(),
  expiryDate: z.string().optional(),
  notes: z.string().optional(),
});

export type ContractFormValues = z.infer<typeof contractSchema>;
