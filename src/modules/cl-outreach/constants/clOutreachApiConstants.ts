// Backend CommunityLink outreach enums — mirror wemarketplus-backend
// communitylink.constants (ClTaskStatus, TicketPriority).
export const CL_TASK_STATUS = {
  Open: 'open',
  InProgress: 'in_progress',
  Completed: 'completed',
  Cancelled: 'cancelled',
} as const;
export type ClTaskStatus = (typeof CL_TASK_STATUS)[keyof typeof CL_TASK_STATUS];

export const TICKET_PRIORITY = {
  Urgent: 'urgent',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
} as const;
export type TicketPriority = (typeof TICKET_PRIORITY)[keyof typeof TICKET_PRIORITY];
