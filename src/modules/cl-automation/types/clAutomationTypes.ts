import type { ID, ISODateString } from '@/shared/types';
import type {
  EnrollmentStatus,
  SequenceAction,
  SequenceTrigger,
} from '../constants/clAutomationConstants';

export interface SequenceStepRecord {
  id: ID;
  stepIndex: number;
  /** Days after the PREVIOUS step. 0 on the first step means "on enrolment". */
  delayDays: number;
  action: SequenceAction;
  title: string;
  body: string | null;
}

export interface SequenceRecord {
  id: ID;
  name: string;
  description: string | null;
  trigger: SequenceTrigger;
  isActive: boolean;
  /** Present on a single read, absent on the list. */
  steps?: SequenceStepRecord[];
  /** Present on a single read. Undefined means "not counted", not zero. */
  activeEnrollments?: number;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

/** `stepIndex` is deliberately absent: order is the array's order. */
export interface SequenceStepInput {
  delayDays: number;
  action: SequenceAction;
  title: string;
  body?: string;
}

export interface CreateSequenceRequest {
  name: string;
  description?: string;
  trigger: SequenceTrigger;
  isActive?: boolean;
  steps: SequenceStepInput[];
}

/** Supplying `steps` replaces the whole set; omitting it leaves them alone. */
export type UpdateSequenceRequest = Partial<CreateSequenceRequest>;

export interface EnrollmentRecord {
  id: ID;
  sequenceId: ID;
  subjectType: string;
  subjectId: ID;
  currentStepIndex: number;
  status: EnrollmentStatus;
  nextFireAt: ISODateString | null;
  lastFiredAt: ISODateString | null;
  stoppedReason: string | null;
  createdAt: ISODateString;
}
