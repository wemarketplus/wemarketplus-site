import { z } from 'zod';
import {
  APARTMENT_STATUS,
  HOUSEKEEPING_STATUS,
  MAINTENANCE_STATUS,
  MAKE_READY_STATUS,
  TICKET_PRIORITY,
} from '../constants/clOperationsApiConstants';

const enumValues = (obj: Record<string, string>) =>
  Object.values(obj) as [string, ...string[]];

// Maintenance ticket form — mirrors POST /cl/maintenance-tickets. issue required.
export const maintenanceSchema = z.object({
  issue: z.string().min(1, 'Required').max(2000),
  ticketNumber: z.string().max(200).optional().or(z.literal('')),
  priority: z.enum(enumValues(TICKET_PRIORITY)),
  status: z.enum(enumValues(MAINTENANCE_STATUS)),
  // Who is working the ticket. Same story as housekeeping's: the column and both
  // DTOs have always accepted it and My Queue filters on it, but no form collected
  // it — so every ticket had assignedTo = null and a technician's queue was empty
  // by construction, whatever the dispatcher did.
  assignedTo: z.string().optional().or(z.literal('')),
  reporterName: z.string().max(200).optional().or(z.literal('')),
  resolution: z.string().max(2000).optional().or(z.literal('')),
});
export type MaintenanceFormValues = z.infer<typeof maintenanceSchema>;

// Housekeeping task form — mirrors POST /cl/housekeeping-tasks. taskType required.
export const housekeepingSchema = z.object({
  taskType: z.string().min(1, 'Required').max(200),
  area: z.string().max(200).optional().or(z.literal('')),
  status: z.enum(enumValues(HOUSEKEEPING_STATUS)),
  // Who is doing the clean. The column and both DTOs have always accepted it; the
  // form never collected it, so every row in the database has assignedTo = null and
  // the guide's "+ Assign Task … if you're assigning cleaning work to someone else
  // on your team" assigned it to nobody.
  assignedTo: z.string().optional().or(z.literal('')),
  dueDate: z.string().optional().or(z.literal('')),
});
export type HousekeepingFormValues = z.infer<typeof housekeepingSchema>;

// Apartment form — mirrors POST /cl/apartments. communityId + unitNumber required.
export const apartmentSchema = z.object({
  communityId: z.string().min(1, 'Pick a community'),
  unitNumber: z.string().min(1, 'Required').max(200),
  unitType: z.string().max(200).optional().or(z.literal('')),
  status: z.enum(enumValues(APARTMENT_STATUS)),
  residentName: z.string().max(200).optional().or(z.literal('')),
  monthlyRate: z
    .string()
    .optional()
    .or(z.literal(''))
    .refine((v) => !v || /^\d+(\.\d{1,2})?$/.test(v), 'Enter an amount like 4200'),
  notes: z.string().max(2000).optional().or(z.literal('')),
});
export type ApartmentFormValues = z.infer<typeof apartmentSchema>;

// Community form — mirrors POST /cl/communities. name required.
export const communitySchema = z.object({
  name: z.string().min(1, 'Required').max(200),
  city: z.string().max(200).optional().or(z.literal('')),
  state: z.string().max(200).optional().or(z.literal('')),
  phone: z.string().max(200).optional().or(z.literal('')),
  address: z.string().max(200).optional().or(z.literal('')),
  /**
   * Blank is allowed — a community can be filed before anyone counts its doors,
   * and `cl_communities.totalUnits` is a non-null integer defaulting to 0, which
   * is what "not recorded yet" looks like in the existing rows.
   *
   * But a TYPED zero is not that. `/^\d+$/` matched "0", so the Add community
   * form accepted a building with no units in it — a community that cannot hold
   * a resident, cannot have an apartment attached, and divides by zero in every
   * occupancy figure (see utils/occupancy). So the count, WHEN GIVEN, starts at
   * one. The two refinements are separate on purpose: "Whole number" and "At
   * least 1 unit" are different mistakes and deserve different messages.
   *
   * Mirrors `@Min(1)` on CreateClCommunityDto/UpdateClCommunityDto — the server
   * is what actually holds the rule; this is the same rule stated where the user
   * can see it.
   */
  totalUnits: z
    .string()
    .optional()
    .or(z.literal(''))
    .refine((v) => !v || /^\d+$/.test(v), 'Whole number')
    .refine((v) => !v || Number(v) >= 1, 'At least 1 unit'),
});
export type CommunityFormValues = z.infer<typeof communitySchema>;

// Make-ready task form — mirrors POST /cl/make-ready-tasks. apartmentId + taskName required.
export const makeReadySchema = z.object({
  apartmentId: z.string().min(1, 'Pick a unit'),
  taskName: z.string().min(1, 'Required').max(200),
  status: z.enum(enumValues(MAKE_READY_STATUS)),
  // The make-ready board is the shared handoff surface both field roles work, so
  // it is the one place an unassigned task is most likely to stall. Same column /
  // DTO / empty-queue story as the other two boards.
  assignedTo: z.string().optional().or(z.literal('')),
  dueDate: z.string().optional().or(z.literal('')),
  notes: z.string().max(2000).optional().or(z.literal('')),
});
export type MakeReadyFormValues = z.infer<typeof makeReadySchema>;
