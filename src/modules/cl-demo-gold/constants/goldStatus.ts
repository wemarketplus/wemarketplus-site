// Status → color / label / badge-tone / cycle maps for the Gold demo. Verbatim
// from the reference's statusColors/statusLabels/statusCls/cycle objects.
// Static values only — no functions (per the modular architecture).
import type { BadgeTone } from '@/shared/cl-demo';
import type { AptStatus, HkStatus, MaintPriority, MaintStatus, TaskPriority } from '../types/goldTypes';

// Raw hex accents (occupancy cards + dashboard unit-status legend).
export const APT_STATUS_COLORS: Record<AptStatus, string> = {
  occupied: '#4fc87a',
  available: '#3d9ee8',
  make_ready: '#f59e0b',
  reserved: '#a78bfa',
  on_notice: '#f87171',
  maintenance: '#f87171',
};

export const APT_STATUS_LABELS: Record<AptStatus, string> = {
  occupied: 'Occupied',
  available: 'Available',
  make_ready: 'Make-Ready',
  reserved: 'Reserved',
  on_notice: 'On-Notice',
  maintenance: 'Maintenance',
};

// Apartments table badge tones (reference statusCls bg/bb/ba/bx/br).
export const APT_STATUS_TONE: Record<AptStatus, BadgeTone> = {
  occupied: 'green',
  available: 'blue',
  make_ready: 'amber',
  reserved: 'neutral',
  on_notice: 'red',
  maintenance: 'red',
};

// Edit Status cycle (reference cycleAptStatus()).
export const APT_STATUS_CYCLE: Record<AptStatus, AptStatus> = {
  occupied: 'on_notice',
  on_notice: 'make_ready',
  make_ready: 'available',
  available: 'reserved',
  reserved: 'occupied',
  maintenance: 'available',
};

// Dashboard "Unit Status" legend rows, in reference order.
export const UNIT_STATUS_ORDER: AptStatus[] = ['occupied', 'available', 'make_ready', 'reserved', 'on_notice'];

export const MAINT_PRIORITY_TONE: Record<MaintPriority, BadgeTone> = {
  urgent: 'red',
  High: 'amber',
  Med: 'blue',
  Low: 'neutral',
};

export const MAINT_STATUS_TONE: Record<MaintStatus, BadgeTone> = {
  open: 'red',
  in_progress: 'amber',
  scheduled: 'blue',
  completed: 'green',
};

// Reference cycle has no 'scheduled' key; `cycle[status] || 'open'` sends it to
// 'open'. Encoded explicitly here to preserve that behavior.
export const MAINT_STATUS_CYCLE: Record<MaintStatus, MaintStatus> = {
  open: 'in_progress',
  in_progress: 'completed',
  completed: 'open',
  scheduled: 'open',
};

export const HK_STATUS_TONE: Record<HkStatus, BadgeTone> = {
  completed: 'green',
  in_progress: 'amber',
  not_started: 'red',
  scheduled: 'blue',
};

// Reference cycle has no 'scheduled' key; `cycle[status] || 'not_started'`
// sends it to 'not_started'. Encoded explicitly here to preserve that.
export const HK_STATUS_CYCLE: Record<HkStatus, HkStatus> = {
  not_started: 'in_progress',
  in_progress: 'completed',
  completed: 'not_started',
  scheduled: 'not_started',
};

// Task priority → accent color (reference rTasks priority span color).
export const TASK_PRIORITY_COLOR: Record<TaskPriority, string> = {
  High: '#f87171',
  Med: '#f59e0b',
  Low: '#4fc87a',
};

// Reports operations-summary badge tone → status label (reference rReports).
export const REPORT_STATUS_LABEL: Record<BadgeTone, string> = {
  green: 'Good',
  red: 'Needs Attention',
  amber: 'Active',
  blue: 'Active',
  neutral: 'Active',
};
