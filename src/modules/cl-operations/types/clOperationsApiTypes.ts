import type { ID, ISODateString } from '@/shared/types';
import type {
  ApartmentStatus,
  ClCareLevel,
  HousekeepingStatus,
  MaintenanceStatus,
  MakeReadyCategory,
  MakeReadyStatus,
  TicketPriority,
} from '../constants/clOperationsApiConstants';

// Backend record shapes for CommunityLink property operations — five resources
// under /api/cl/* (communities, apartments, make-ready/maintenance/housekeeping).
interface Base {
  id: ID;
  tenantId: ID;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface ClCommunityRecord extends Base {
  name: string;
  address: string | null;
  city: string | null;
  state: string | null;
  phone: string | null;
  careTypes: ClCareLevel[] | null;
  totalUnits: number | null;
}

export interface ClApartmentRecord extends Base {
  communityId: ID;
  unitNumber: string;
  unitType: string | null;
  careLevel: ClCareLevel | null;
  sqFt: number | null;
  floor: number | null;
  status: ApartmentStatus;
  residentName: string | null;
  moveInDate: string | null;
  moveOutDate: string | null;
  monthlyRate: number | null;
  careLevelNum: number | null;
  notes: string | null;
}

export interface ClMakeReadyTaskRecord extends Base {
  apartmentId: ID;
  taskName: string;
  category: MakeReadyCategory | null;
  status: MakeReadyStatus;
  assignedTo: ID | null;
  dueDate: string | null;
  notes: string | null;
}

export interface ClMaintenanceTicketRecord extends Base {
  apartmentId: ID | null;
  ticketNumber: string | null;
  issue: string;
  priority: TicketPriority;
  status: MaintenanceStatus;
  assignedTo: ID | null;
  reporterName: string | null;
  resolution: string | null;
}

export interface ClHousekeepingTaskRecord extends Base {
  apartmentId: ID | null;
  taskType: string;
  area: string | null;
  status: HousekeepingStatus;
  assignedTo: ID | null;
  dueDate: string | null;
}

// Request bodies (create; update = Partial).
export interface CreateClApartmentRequest {
  communityId: string;
  unitNumber: string;
  unitType?: string;
  careLevel?: ClCareLevel;
  sqFt?: number;
  floor?: number;
  status?: ApartmentStatus;
  residentName?: string;
  moveInDate?: string;
  moveOutDate?: string;
  monthlyRate?: number;
  careLevelNum?: number;
  notes?: string;
}
export interface CreateClMakeReadyTaskRequest {
  apartmentId: string;
  taskName: string;
  category?: MakeReadyCategory;
  status?: MakeReadyStatus;
  assignedTo?: string;
  dueDate?: string;
  notes?: string;
}
export interface CreateClMaintenanceTicketRequest {
  apartmentId?: string;
  ticketNumber?: string;
  issue: string;
  priority?: TicketPriority;
  status?: MaintenanceStatus;
  assignedTo?: string;
  reporterName?: string;
  resolution?: string;
}
export interface CreateClHousekeepingTaskRequest {
  apartmentId?: string;
  taskType: string;
  area?: string;
  status?: HousekeepingStatus;
  assignedTo?: string;
  dueDate?: string;
}
export interface CreateClCommunityRequest {
  name: string;
  address?: string;
  city?: string;
  state?: string;
  phone?: string;
  careTypes?: ClCareLevel[];
  totalUnits?: number;
}
