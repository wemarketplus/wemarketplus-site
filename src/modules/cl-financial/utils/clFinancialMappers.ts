import { opt } from '@/shared/ui/entity';
import type {
  ClRevenueEntryRecord,
  ClConcessionRecord,
  ClCompetitorRecord,
  ClLeakageItemRecord,
  ClLocPricingRecord,
  CreateClRevenueEntryRequest,
  CreateClConcessionRequest,
  CreateClCompetitorRequest,
  CreateClLeakageItemRequest,
  CreateClLocPricingRequest,
} from '../types/clFinancialApiTypes';
import type {
  RevenueFormValues,
  ConcessionFormValues,
  CompetitorFormValues,
  LeakageFormValues,
  LocFormValues,
} from '../schema/clFinancialSchema';
import type { ConcessionStatus, LeakageStatus } from '../constants/clFinancialApiConstants';

const optNum = (v: string | undefined): number | undefined =>
  v?.trim() ? Number(v) : undefined;

// Postgres numeric columns arrive as strings via TypeORM — coerce for display.
export const num = (v: number | string | null | undefined): number =>
  v == null || v === '' ? 0 : Number(v);

// --- revenue -------------------------------------------------------------

export function toCreateRevenue(v: RevenueFormValues): CreateClRevenueEntryRequest {
  return {
    entryDate: v.entryDate,
    amount: Number(v.amount),
    ...opt('category', v.category),
    ...(v.budgetAmount?.trim() ? { budgetAmount: Number(v.budgetAmount) } : {}),
    ...opt('description', v.description),
  };
}
export function toUpdateRevenue(v: RevenueFormValues): Partial<CreateClRevenueEntryRequest> {
  return toCreateRevenue(v);
}
export function toRevenueFormValues(r: ClRevenueEntryRecord): RevenueFormValues {
  return {
    entryDate: r.entryDate,
    category: r.category ?? '',
    amount: r.amount != null ? String(num(r.amount)) : '',
    budgetAmount: r.budgetAmount != null ? String(num(r.budgetAmount)) : '',
    description: r.description ?? '',
  };
}

// --- concessions ---------------------------------------------------------

export function toCreateConcession(v: ConcessionFormValues): CreateClConcessionRequest {
  return {
    type: v.type.trim(),
    status: v.status as ConcessionStatus,
    ...(v.valueAmount?.trim() ? { valueAmount: Number(v.valueAmount) } : {}),
    ...opt('reason', v.reason),
  };
}
export function toUpdateConcession(v: ConcessionFormValues): Partial<CreateClConcessionRequest> {
  return toCreateConcession(v);
}
export function toConcessionFormValues(c: ClConcessionRecord): ConcessionFormValues {
  return {
    type: c.type,
    valueAmount: c.valueAmount != null ? String(num(c.valueAmount)) : '',
    status: c.status,
    reason: c.reason ?? '',
  };
}

// --- competitors ---------------------------------------------------------

export function toCreateCompetitor(v: CompetitorFormValues): CreateClCompetitorRequest {
  return {
    name: v.name.trim(),
    ...opt('city', v.city),
    ...(optNum(v.distanceMiles) != null ? { distanceMiles: optNum(v.distanceMiles) } : {}),
    ...(optNum(v.rateIl) != null ? { rateIl: optNum(v.rateIl) } : {}),
    ...(optNum(v.rateAl) != null ? { rateAl: optNum(v.rateAl) } : {}),
    ...(optNum(v.rateMc) != null ? { rateMc: optNum(v.rateMc) } : {}),
    ...(optNum(v.occupancyPct) != null ? { occupancyPct: optNum(v.occupancyPct) } : {}),
    ...opt('notes', v.notes),
  };
}
export function toUpdateCompetitor(v: CompetitorFormValues): Partial<CreateClCompetitorRequest> {
  return toCreateCompetitor(v);
}
export function toCompetitorFormValues(c: ClCompetitorRecord): CompetitorFormValues {
  return {
    name: c.name,
    city: c.city ?? '',
    distanceMiles: c.distanceMiles != null ? String(num(c.distanceMiles)) : '',
    rateIl: c.rateIl != null ? String(num(c.rateIl)) : '',
    rateAl: c.rateAl != null ? String(num(c.rateAl)) : '',
    rateMc: c.rateMc != null ? String(num(c.rateMc)) : '',
    occupancyPct: c.occupancyPct != null ? String(num(c.occupancyPct)) : '',
    notes: c.notes ?? '',
  };
}

// --- LOC pricing ---------------------------------------------------------

export function toCreateLoc(v: LocFormValues): CreateClLocPricingRequest {
  return {
    level: Number(v.level),
    label: v.label.trim(),
    addOnRate: Number(v.addOnRate),
    ...opt('description', v.description),
  };
}
export function toUpdateLoc(v: LocFormValues): Partial<CreateClLocPricingRequest> {
  return toCreateLoc(v);
}
export function toLocFormValues(l: ClLocPricingRecord): LocFormValues {
  return {
    level: String(l.level),
    label: l.label,
    description: l.description ?? '',
    addOnRate: l.addOnRate != null ? String(num(l.addOnRate)) : '',
  };
}

// --- revenue leakage -------------------------------------------------------

export function toCreateLeakage(v: LeakageFormValues): CreateClLeakageItemRequest {
  return {
    issue: v.issue.trim(),
    type: v.type.trim(),
    status: v.status as LeakageStatus,
    ...(v.monthlyImpact?.trim() ? { monthlyImpact: Number(v.monthlyImpact) } : {}),
    ...opt('notes', v.notes),
  };
}
export function toUpdateLeakage(v: LeakageFormValues): Partial<CreateClLeakageItemRequest> {
  return toCreateLeakage(v);
}
export function toLeakageFormValues(l: ClLeakageItemRecord): LeakageFormValues {
  return {
    issue: l.issue,
    type: l.type,
    monthlyImpact: l.monthlyImpact != null ? String(num(l.monthlyImpact)) : '',
    status: l.status,
    notes: l.notes ?? '',
  };
}
