import { CareLevel } from '@/shared/types';
import type { Apartment, MakeReadyTicket, ServiceTicket } from '@/shared/types';
import type {
  ClApartmentRecord,
  ClHousekeepingTaskRecord,
  ClMaintenanceTicketRecord,
  ClMakeReadyTaskRecord,
} from '../types/clOperationsApiTypes';

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

// Backend make-ready is per-task; the UI ticket is per-unit progress. Show one
// row per task with completion derived from status.
export function toMakeReady(t: ClMakeReadyTaskRecord): MakeReadyTicket {
  const pct = t.status === 'completed' ? 1 : t.status === 'in_progress' ? 0.5 : 0;
  return {
    id: t.id,
    unitNumber: t.apartmentId,
    unitType: t.taskName,
    moveOutDate: t.createdAt,
    targetDate: t.dueDate ?? t.updatedAt,
    pctComplete: pct,
    assignedTo: t.assignedTo ?? '',
  };
}

export function toMaintenanceTicket(t: ClMaintenanceTicketRecord): ServiceTicket {
  const status = t.status === 'completed' ? 'completed' : t.status === 'in_progress' ? 'in_progress' : 'open';
  return {
    id: t.id,
    unitNumber: t.apartmentId ?? '',
    title: t.issue,
    priority: t.priority as ServiceTicket['priority'],
    status: status as ServiceTicket['status'],
    assignedTo: t.assignedTo ?? '',
    description: t.resolution ?? undefined,
  };
}

export function toHousekeepingTicket(t: ClHousekeepingTaskRecord): ServiceTicket {
  const status = t.status === 'completed' ? 'completed' : t.status === 'in_progress' ? 'in_progress' : 'open';
  return {
    id: t.id,
    unitNumber: t.apartmentId ?? '',
    title: t.taskType,
    priority: 'medium',
    status: status as ServiceTicket['status'],
    assignedTo: t.assignedTo ?? '',
    description: t.area ?? undefined,
  };
}
