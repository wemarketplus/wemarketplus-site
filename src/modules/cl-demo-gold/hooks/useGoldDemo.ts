// Orchestration hook for the Gold demo: exposes slice state plus the demo's
// "business logic" entry points (prompt-driven adds, status cycles, toasts) so
// view components stay presentational and never touch dispatch/selectors.
// Handlers read live state for their toast copy, so they are rebuilt each
// render rather than memoized (mirrors the reference's imperative handlers).
import { cap } from '@/shared/cl-demo';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { LEAD_STATUS_CYCLE } from '../constants/goldData';
import {
  APT_STATUS_CYCLE,
  HK_STATUS_CYCLE,
  MAINT_STATUS_CYCLE,
} from '../constants/goldStatus';
import { goldDemoActions as A } from '../store/goldDemoSlice';
import type { GoldRole, GoldTabKey, NewTaskInput } from '../types/goldTypes';

function todayPlus(days: number): string {
  return new Date(Date.now() + days * 86400000).toISOString().split('T')[0];
}

export function useGoldDemo() {
  const dispatch = useAppDispatch();
  const state = useAppSelector((s) => s.goldDemo);

  const toast = (message: string, error = false) => dispatch(A.showToast(message, error));

  const actions = {
    setTab: (tab: GoldTabKey) => dispatch(A.setTab(tab)),
    setRole: (role: GoldRole) => dispatch(A.setRole(role)),
    toast,
    hideToast: () => dispatch(A.hideToast()),

    // ── Leads ──────────────────────────────────────────────────────
    promptAddLead: () => {
      const name = window.prompt('New lead full name:');
      if (!name) return;
      const care =
        window.prompt('Care level (Independent Living / Assisted Living / Memory Care):', 'Independent Living') ||
        'Independent Living';
      dispatch(A.addLead({ name, care }));
      toast('Lead added: ' + name);
    },
    cycleLeadStatus: (id: number) => {
      const lead = state.leads.find((l) => l.id === id);
      if (!lead) return;
      const next = LEAD_STATUS_CYCLE[(LEAD_STATUS_CYCLE.indexOf(lead.status) + 1) % LEAD_STATUS_CYCLE.length];
      dispatch(A.cycleLeadStatus(id));
      toast(lead.name + ' → ' + next);
    },

    // ── Referrals ──────────────────────────────────────────────────
    promptAddRef: () => {
      const name = window.prompt('Referral contact name:');
      if (!name) return;
      const org = window.prompt('Organization:', '') || '';
      dispatch(A.addReferral({ name, org }));
      toast('Source added: ' + name);
    },
    logRefVisit: (id: number) => {
      const ref = state.referrals.find((r) => r.id === id);
      if (!ref) return;
      dispatch(A.logRefVisit(id));
      toast('Visit logged for ' + ref.name);
    },

    // ── Apartments ─────────────────────────────────────────────────
    promptAddApt: () => {
      const unit = window.prompt('Unit number:');
      if (!unit) return;
      const type = window.prompt('Unit type (Studio/1BR/2BR):', '1BR/1BA') || 'Studio';
      const care = window.prompt('Care level (IL/AL/MC):', 'IL') || 'IL';
      dispatch(A.addApt({ unit, type, care }));
      toast('Unit ' + unit + ' added!');
    },
    cycleAptStatus: (id: number) => {
      const apt = state.apts.find((a) => a.id === id);
      if (!apt) return;
      const next = APT_STATUS_CYCLE[apt.status] || 'available';
      dispatch(A.cycleAptStatus(id));
      toast('Unit ' + apt.unit + ' → ' + next.replace(/_/g, ' '));
    },
    scheduleMakeReady: (id: number) => {
      const apt = state.apts.find((a) => a.id === id);
      if (!apt) return;
      dispatch(A.scheduleMakeReady(id));
      dispatch(A.setTab('makeready'));
      toast('Make-ready ticket created for Unit ' + apt.unit + '!');
    },

    // ── Make-ready ─────────────────────────────────────────────────
    promptAddMr: () => {
      const unit = window.prompt('Unit number:');
      if (!unit) return;
      const target = window.prompt('Target ready date (YYYY-MM-DD):', todayPlus(14)) || 'TBD';
      dispatch(A.addMrTicket({ unit, target }));
      toast('Make-ready ticket created for Unit ' + unit + '!');
    },
    toggleMrTask: (id: number, idx: number) => {
      dispatch(A.toggleMrTask({ id, idx }));
      toast('Task updated!');
    },
    advanceMr: (id: number) => {
      const ticket = state.mrTickets.find((t) => t.id === id);
      if (!ticket) return;
      dispatch(A.advanceMr(id));
      toast('Progress: ' + Math.min(100, ticket.pct + 25) + '%');
    },
    completeMr: (id: number) => {
      dispatch(A.completeMr(id));
      toast('Unit marked lease-ready! ✓');
    },

    // ── Maintenance ────────────────────────────────────────────────
    promptAddMaint: () => {
      const issue = window.prompt('Describe the maintenance issue:');
      if (!issue) return;
      const unit = window.prompt('Unit number:', '') || 'Common';
      dispatch(A.addMaint({ unit, issue }));
      toast('Ticket created!');
    },
    cycleMaintStatus: (id: number) => {
      const ticket = state.maintTickets.find((t) => t.id === id);
      if (!ticket) return;
      const next = MAINT_STATUS_CYCLE[ticket.status] || 'open';
      dispatch(A.cycleMaintStatus(id));
      toast('Ticket status: ' + cap(next.replace(/_/g, ' ')));
    },

    // ── Housekeeping ───────────────────────────────────────────────
    promptAddHk: () => {
      const task = window.prompt('Task description:');
      if (!task) return;
      const unit = window.prompt('Unit or area:', 'Common') || 'Common';
      dispatch(A.addHk({ task, unit }));
      toast('Task assigned!');
    },
    cycleHkStatus: (id: number) => {
      const task = state.hkTasks.find((t) => t.id === id);
      if (!task) return;
      const next = HK_STATUS_CYCLE[task.status] || 'not_started';
      dispatch(A.cycleHkStatus(id));
      toast(next === 'completed' ? 'Task complete! ✓' : 'Status updated.');
    },

    // ── Tasks ──────────────────────────────────────────────────────
    setTaskForm: (open: boolean) => dispatch(A.setTaskForm(open)),
    addTask: (input: NewTaskInput) => {
      dispatch(A.addTask(input));
      toast('Task added!');
    },
    toggleTask: (id: number, done: boolean) => {
      dispatch(A.toggleTask({ id, done }));
      toast(done ? 'Done!' : 'Reopened.');
    },
    deleteTask: (id: number) => {
      dispatch(A.deleteTask(id));
      toast('Removed.');
    },

    // ── Tours (inline form only) ───────────────────────────────────
    setTourForm: (open: boolean) => dispatch(A.setTourForm(open)),
    saveTour: (name: string, date: string) => {
      if (!name || !date) {
        toast('Name and date required.', true);
        return;
      }
      toast('Tour scheduled for ' + name + ' on ' + date + '!');
      dispatch(A.setTourForm(false));
    },
  };

  return { ...state, actions };
}
