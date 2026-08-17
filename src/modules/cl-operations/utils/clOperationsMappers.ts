import { CareLevel } from '@/shared/types';
import type { Apartment } from '@/shared/types';
import { opt } from '@/shared/ui/entity';
import type {
  ClApartmentRecord,
  ClCommunityRecord,
  ClHousekeepingTaskRecord,
  ClMaintenanceTicketRecord,
  ClMakeReadyTaskRecord,
  CreateClApartmentRequest,
  CreateClCommunityRequest,
  CreateClHousekeepingTaskRequest,
  CreateClMaintenanceTicketRequest,
  CreateClMakeReadyTaskRequest,
} from '../types/clOperationsApiTypes';
import type {
  ApartmentFormValues,
  CommunityFormValues,
  HousekeepingFormValues,
  MaintenanceFormValues,
  MakeReadyFormValues,
} from '../schema/clOperationsSchema';
import type {
  ApartmentStatus,
  HousekeepingStatus,
  MaintenanceStatus,
  MakeReadyStatus,
  TicketPriority,
} from '../constants/clOperationsApiConstants';

// --- form <-> DTO mappers (create/edit) ---------------------------------

export function toCreateMaintenance(
  v: MaintenanceFormValues,
): CreateClMaintenanceTicketRequest {
  return {
    issue: v.issue.trim(),
    priority: v.priority as TicketPriority,
    status: v.status as MaintenanceStatus,
    ...opt('ticketNumber', v.ticketNumber),
    // `opt` drops a blank rather than sending '': assignedTo is @IsUUID() on the
    // DTO, so an empty string would 400 the save. Omitting it leaves the ticket
    // unassigned — a real state, since a ticket is often logged before anyone
    // decides who takes it.
    ...opt('assignedTo', v.assignedTo),
    ...opt('reporterName', v.reporterName),
    ...opt('resolution', v.resolution),
  };
}
export function toMaintenanceFormValues(t: ClMaintenanceTicketRecord): MaintenanceFormValues {
  return {
    issue: t.issue,
    ticketNumber: t.ticketNumber ?? '',
    priority: t.priority,
    status: t.status,
    assignedTo: t.assignedTo ?? '',
    reporterName: t.reporterName ?? '',
    resolution: t.resolution ?? '',
  };
}

export function toCreateHousekeeping(
  v: HousekeepingFormValues,
): CreateClHousekeepingTaskRequest {
  return {
    taskType: v.taskType.trim(),
    status: v.status as HousekeepingStatus,
    ...opt('area', v.area),
    // `opt` drops a blank rather than sending '': assignedTo is @IsUUID() on the
    // DTO, so an empty string would 400 the whole save. Omitting it leaves the task
    // unassigned, which is a legitimate state — a supervisor can add a task to the
    // board before deciding who cleans it.
    ...opt('assignedTo', v.assignedTo),
    ...opt('dueDate', v.dueDate),
  };
}
export function toHousekeepingFormValues(t: ClHousekeepingTaskRecord): HousekeepingFormValues {
  return {
    taskType: t.taskType,
    area: t.area ?? '',
    status: t.status,
    assignedTo: t.assignedTo ?? '',
    dueDate: t.dueDate ?? '',
  };
}

export function toCreateApartment(
  v: ApartmentFormValues,
): CreateClApartmentRequest {
  return {
    communityId: v.communityId,
    unitNumber: v.unitNumber.trim(),
    status: v.status as ApartmentStatus,
    ...opt('unitType', v.unitType),
    ...opt('residentName', v.residentName),
    ...(v.monthlyRate?.trim() ? { monthlyRate: Number(v.monthlyRate) } : {}),
    ...opt('notes', v.notes),
  };
}
export function toApartmentFormValues(a: ClApartmentRecord): ApartmentFormValues {
  return {
    communityId: a.communityId,
    unitNumber: a.unitNumber,
    unitType: a.unitType ?? '',
    status: a.status,
    residentName: a.residentName ?? '',
    monthlyRate: a.monthlyRate != null ? String(a.monthlyRate) : '',
    notes: a.notes ?? '',
  };
}

export function toCreateMakeReady(
  v: MakeReadyFormValues,
): CreateClMakeReadyTaskRequest {
  return {
    apartmentId: v.apartmentId,
    taskName: v.taskName.trim(),
    status: v.status as MakeReadyStatus,
    // Blank omitted, not sent as '' — see toCreateMaintenance for why.
    ...opt('assignedTo', v.assignedTo),
    ...opt('dueDate', v.dueDate),
    ...opt('notes', v.notes),
  };
}
export function toMakeReadyFormValues(t: ClMakeReadyTaskRecord): MakeReadyFormValues {
  return {
    apartmentId: t.apartmentId,
    taskName: t.taskName,
    status: t.status,
    assignedTo: t.assignedTo ?? '',
    dueDate: t.dueDate ?? '',
    notes: t.notes ?? '',
  };
}

// Pure data-transformation helpers mapping backend cl/* records onto the UI
// view-models. Kept in utils/ so the hook stays orchestration-only.

export function toApartment(a: ClApartmentRecord): Apartment {
  return {
    id: a.id,
    unitNumber: a.unitNumber,
    unitType: a.unitType ?? '',
    careLevel: (a.careLevel ?? CareLevel.IL) as Apartment['careLevel'],
    status: a.status as Apartment['status'],
    residentName: a.residentName ?? undefined,
    monthlyRate: a.monthlyRate ?? 0,
    openMakeReadyTasks: 0,
  };
}


// --- communities ---------------------------------------------------------

export function toCreateCommunity(v: CommunityFormValues): CreateClCommunityRequest {
  return {
    name: v.name.trim(),
    ...opt('city', v.city),
    ...opt('state', v.state),
    ...opt('phone', v.phone),
    ...opt('address', v.address),
    ...(v.totalUnits?.trim() ? { totalUnits: Number(v.totalUnits) } : {}),
  };
}
export function toUpdateCommunity(v: CommunityFormValues): Partial<CreateClCommunityRequest> {
  return toCreateCommunity(v);
}
export function toCommunityFormValues(c: ClCommunityRecord): CommunityFormValues {
  return {
    name: c.name,
    city: c.city ?? '',
    state: c.state ?? '',
    phone: c.phone ?? '',
    address: c.address ?? '',
    totalUnits: c.totalUnits != null ? String(c.totalUnits) : '',
  };
}
