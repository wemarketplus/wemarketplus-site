// Status → color / label / badge-tone / cycle maps for the Max demo. Verbatim
// from the reference's statusColors/statusLabels/statusCls/cycle objects.
// Static values only.
import type { BadgeTone } from '@/shared/cl-demo';

export const APT_STATUS_COLORS: Record<string, string> = {
  occupied: '#4fc87a', available: '#3d9ee8', make_ready: '#f59e0b',
  reserved: '#a78bfa', on_notice: '#f87171', maintenance: '#f87171',
};
export const APT_STATUS_LABELS: Record<string, string> = {
  occupied: 'Occupied', available: 'Available', make_ready: 'Make-Ready',
  reserved: 'Reserved', on_notice: 'On-Notice', maintenance: 'Maintenance', offline: 'Offline',
};
export const APT_STATUS_TONE: Record<string, BadgeTone> = {
  occupied: 'green', available: 'blue', make_ready: 'amber',
  reserved: 'neutral', on_notice: 'red', maintenance: 'red',
};
export const APT_STATUS_CYCLE: Record<string, string> = {
  occupied: 'on_notice', on_notice: 'make_ready', make_ready: 'available',
  available: 'reserved', reserved: 'occupied', maintenance: 'available',
};
export const UNIT_STATUS_ORDER = ['occupied', 'available', 'make_ready', 'reserved', 'on_notice'];

export const MAINT_PRIORITY_TONE: Record<string, BadgeTone> = {
  urgent: 'red', High: 'amber', Med: 'blue', Low: 'neutral',
};
export const MAINT_STATUS_TONE: Record<string, BadgeTone> = {
  open: 'red', in_progress: 'amber', scheduled: 'blue', completed: 'green',
};
export const MAINT_STATUS_CYCLE: Record<string, string> = {
  open: 'in_progress', in_progress: 'completed', completed: 'open',
};

export const HK_STATUS_TONE: Record<string, BadgeTone> = {
  completed: 'green', in_progress: 'amber', not_started: 'red', scheduled: 'blue',
};
export const HK_STATUS_CYCLE: Record<string, string> = {
  not_started: 'in_progress', in_progress: 'completed', completed: 'not_started',
};

// Concession approval status maps (rConcessions).
export const CONCESSION_STATUS_TONE: Record<string, BadgeTone> = { approved: 'green', denied: 'red', pending: 'amber' };
export const CONCESSION_VALUE_COLOR: Record<string, string> = { approved: '#4fc87a', denied: '#f87171', pending: '#f59e0b' };

// Task priority → label color (rTasks).
export const TASK_PRIORITY_COLOR: Record<string, string> = { High: '#f87171', Med: '#f59e0b', Urgent: '#f87171', Normal: '#4fc87a', Low: '#4fc87a' };

// Reports operations-summary status label per badge tone (rReports).
export const REPORT_STATUS_LABEL: Record<BadgeTone, string> = { green: 'Good', red: 'Needs Attention', amber: 'Active', blue: 'Active', neutral: 'Active' };

// Revenue-leakage status → badge class (rRevenue).
export const LEAK_STATUS_CLS: Record<string, string> = { ongoing: 'bg-[#f87171]/10 text-[#f87171]', review: 'bg-[#f59e0b]/10 text-[#f59e0b]', active: 'bg-[#f59e0b]/10 text-[#f59e0b]', fix_needed: 'bg-[#f87171]/10 text-[#f87171]', pending: 'bg-white/[0.07] text-[#8ba4c4]' };
