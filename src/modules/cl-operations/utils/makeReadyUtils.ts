import type { MakeReadyTicket } from '@/shared/types';

export function getMakeReadyDisplayData(ticket: MakeReadyTicket): { pct: number; overdue: boolean } {
  const pct = Math.round(ticket.pctComplete * 100);
  const overdue = new Date(ticket.targetDate).getTime() < Date.now() && pct < 100;
  return { pct, overdue };
}
