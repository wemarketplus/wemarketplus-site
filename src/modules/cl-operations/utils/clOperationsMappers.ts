import { CareLevel } from '@/shared/types';
import type { Apartment } from '@/shared/types';
import { opt, optOrNull } from '@/shared/ui/entity';
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
    // `optOrNull`, not `opt`. Both avoid sending '' to an @IsUUID field, but
    // `opt` omits the key entirely — and an omitted key in a PATCH means "leave
    // unchanged", so clearing Assigned to could never actually unassign a
    // ticket. An explicit null does: @IsOptional skips validation on null and
    // the column is nullable. Same fix as cl-tasks/tasksUtils.ts.
    ...optOrNull('assignedTo', v.assignedTo),
    ...optOrNull('reporterName', v.reporterName),
    ...optOrNull('resolution', v.resolution),
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
    ...optOrNull('area', v.area),
    // Clearable — see toCreateMaintenance above for why this is optOrNull.
    ...optOrNull('assignedTo', v.assignedTo),
    ...optOrNull('dueDate', v.dueDate),
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
    // Clearable — see toCreateMaintenance above for why this is optOrNull.
    ...optOrNull('assignedTo', v.assignedTo),
    ...optOrNull('dueDate', v.dueDate),
    ...optOrNull('notes', v.notes),
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
    /**
     * A stored 0 opens the field BLANK, not as "0".
     *
     * `totalUnits` is a non-null integer column defaulting to 0, so every
     * community created before the count was collected holds 0 — it means "never
     * recorded", not "this building has no units". Now that the schema requires
     * at least 1, echoing that 0 back into the input would make the Edit form
     * un-submittable for those rows: someone fixing a phone number would be
     * blocked by a units error about a value they never entered. Blank is both
     * honest about what is known and valid to save.
     */
    totalUnits: c.totalUnits ? String(c.totalUnits) : '',
  };
}
