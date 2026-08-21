// Redux slice holding the Gold demo's mutable in-memory state. Mirrors the
// reference's module-level arrays + nextId counter, plus UI state (active tab,
// role, page title, inline form toggles, toast). All mutations route through
// these reducers so every view reads a single source of truth.
import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ToastState } from '@/shared/cl-demo';
import {
  SEED_APTS,
  SEED_HK_TASKS,
  SEED_LEADS,
  SEED_MAINT_TICKETS,
  SEED_MR_TICKETS,
  SEED_NEXT_ID,
  SEED_REFERRALS,
  SEED_TASKS,
  LEAD_STATUS_CYCLE,
} from '../constants/goldData';
import {
  INITIAL_PAGE_TITLE,
  ROLE_DEFAULT_TAB,
  TAB_TITLES,
} from '../constants/goldNav';
import {
  APT_STATUS_CYCLE,
  HK_STATUS_CYCLE,
  MAINT_STATUS_CYCLE,
} from '../constants/goldStatus';
import type {
  Apartment,
  GoldRole,
  GoldTabKey,
  HkTask,
  Lead,
  MaintTicket,
  MrTicket,
  NewApartmentInput,
  NewHkInput,
  NewLeadInput,
  NewMaintInput,
  NewMrTicketInput,
  NewReferralInput,
  NewTaskInput,
  Referral,
  Task,
} from '../types/goldTypes';

interface GoldDemoState {
  leads: Lead[];
  apts: Apartment[];
  mrTickets: MrTicket[];
  maintTickets: MaintTicket[];
  hkTasks: HkTask[];
  referrals: Referral[];
  tasks: Task[];
  role: GoldRole;
  activeTab: GoldTabKey;
  pageTitle: string;
  nextId: number;
  taskFormOpen: boolean;
  tourFormOpen: boolean;
  toast: ToastState | null;
}

const initialState: GoldDemoState = {
  leads: SEED_LEADS.map((l) => ({ ...l })),
  apts: SEED_APTS.map((a) => ({ ...a })),
  mrTickets: SEED_MR_TICKETS.map((t) => ({ ...t, tasks: [...t.tasks] })),
  maintTickets: SEED_MAINT_TICKETS.map((t) => ({ ...t })),
  hkTasks: SEED_HK_TASKS.map((t) => ({ ...t })),
  referrals: SEED_REFERRALS.map((r) => ({ ...r })),
  tasks: SEED_TASKS.map((t) => ({ ...t })),
  role: 'director',
  activeTab: 'dashboard',
  pageTitle: INITIAL_PAGE_TITLE,
  nextId: SEED_NEXT_ID,
  taskFormOpen: false,
  tourFormOpen: false,
  toast: null,
};

function todayIso(): string {
  return new Date().toISOString().split('T')[0];
}
function tomorrowIso(): string {
  return new Date(Date.now() + 86400000).toISOString().split('T')[0];
}

const goldDemoSlice = createSlice({
  name: 'goldDemo',
  initialState,
  reducers: {
    setTab(state, action: PayloadAction<GoldTabKey>) {
      state.activeTab = action.payload;
      state.pageTitle = TAB_TITLES[action.payload];
      state.taskFormOpen = false;
      state.tourFormOpen = false;
    },
    setRole(state, action: PayloadAction<GoldRole>) {
      state.role = action.payload;
      const tab = ROLE_DEFAULT_TAB[action.payload];
      state.activeTab = tab;
      state.pageTitle =
        tab === 'maintenance'
          ? 'Maintenance Tickets'
          : tab === 'housekeeping'
            ? 'Housekeeping Tasks'
            : 'Dashboard';
      state.taskFormOpen = false;
      state.tourFormOpen = false;
    },

    // ── Toast ────────────────────────────────────────────────────────
    showToast: {
      reducer(state, action: PayloadAction<ToastState>) {
        state.toast = action.payload;
      },
      prepare(message: string, error = false) {
        return { payload: { message, error, nonce: Math.random() } };
      },
    },
    hideToast(state) {
      state.toast = null;
    },

    // ── Leads ────────────────────────────────────────────────────────
    addLead(state, action: PayloadAction<NewLeadInput>) {
      state.nextId += 1;
      state.leads.unshift({
        id: state.nextId,
        name: action.payload.name,
        care: action.payload.care,
        status: 'Inquiry',
        urgency: 'Medium',
        source: 'Direct',
        phone: '',
        fu: '',
        notes: '',
      });
    },
    cycleLeadStatus(state, action: PayloadAction<number>) {
      const lead = state.leads.find((l) => l.id === action.payload);
      if (!lead) return;
      const idx = LEAD_STATUS_CYCLE.indexOf(lead.status);
      lead.status = LEAD_STATUS_CYCLE[(idx + 1) % LEAD_STATUS_CYCLE.length];
    },

    // ── Referrals ────────────────────────────────────────────────────
    addReferral(state, action: PayloadAction<NewReferralInput>) {
      state.nextId += 1;
      state.referrals.push({
        id: state.nextId,
        name: action.payload.name,
        type: 'Physician',
        org: action.payload.org,
        leads: 0,
        last: '—',
      });
    },
    logRefVisit(state, action: PayloadAction<number>) {
      const ref = state.referrals.find((r) => r.id === action.payload);
      if (!ref) return;
      ref.leads += 1;
      ref.last = todayIso();
    },

    // ── Apartments ───────────────────────────────────────────────────
    addApt(state, action: PayloadAction<NewApartmentInput>) {
      state.nextId += 1;
      state.apts.push({
        id: state.nextId,
        unit: action.payload.unit,
        type: action.payload.type,
        care: action.payload.care,
        sqft: 0,
        status: 'available',
        resident: '',
        rate: 0,
        mrTasks: 0,
      });
    },
    cycleAptStatus(state, action: PayloadAction<number>) {
      const apt = state.apts.find((a) => a.id === action.payload);
      if (!apt) return;
      apt.status = APT_STATUS_CYCLE[apt.status] || 'available';
    },
    // Mirrors scheduleMR(): converts a unit to make-ready and opens a ticket.
    scheduleMakeReady(state, action: PayloadAction<number>) {
      const apt = state.apts.find((a) => a.id === action.payload);
      if (!apt) return;
      apt.status = 'make_ready';
      apt.mrTasks = 5;
      state.nextId += 1;
      state.mrTickets.push({
        id: state.nextId,
        unit: apt.unit,
        type: apt.type,
        moveout: '2026-02-28',
        target: '2026-03-10',
        pct: 0,
        tasks: ['Trash out', 'Locks changed', 'Paint', 'Cleaning', 'Inspection'],
        assignee: 'TBD',
      });
    },

    // ── Make-ready ───────────────────────────────────────────────────
    addMrTicket(state, action: PayloadAction<NewMrTicketInput>) {
      state.nextId += 1;
      state.mrTickets.push({
        id: state.nextId,
        unit: action.payload.unit,
        type: 'Unit',
        moveout: 'TBD',
        target: action.payload.target,
        pct: 0,
        tasks: ['Trash out', 'Locks changed', 'Cleaning', 'Inspection'],
        assignee: 'TBD',
      });
    },
    toggleMrTask(state, action: PayloadAction<{ id: number; idx: number }>) {
      const ticket = state.mrTickets.find((t) => t.id === action.payload.id);
      if (!ticket) return;
      const task = ticket.tasks[action.payload.idx];
      ticket.tasks[action.payload.idx] = task.startsWith('done:') ? task.slice(5) : 'done:' + task;
      const done = ticket.tasks.filter((x) => x.startsWith('done:')).length;
      ticket.pct = Math.round((done / ticket.tasks.length) * 100);
    },
    advanceMr(state, action: PayloadAction<number>) {
      const ticket = state.mrTickets.find((t) => t.id === action.payload);
      if (!ticket) return;
      ticket.pct = Math.min(100, ticket.pct + 25);
    },
    completeMr(state, action: PayloadAction<number>) {
      const ticket = state.mrTickets.find((t) => t.id === action.payload);
      if (!ticket) return;
      ticket.pct = 100;
      ticket.tasks = ticket.tasks.map((x) => (x.startsWith('done:') ? x : 'done:' + x));
    },

    // ── Maintenance ──────────────────────────────────────────────────
    addMaint(state, action: PayloadAction<NewMaintInput>) {
      state.nextId += 1;
      state.maintTickets.push({
        id: state.nextId,
        ticket: 'M-' + (state.maintTickets.length + 1).toString().padStart(3, '0'),
        unit: action.payload.unit,
        resident: '',
        issue: action.payload.issue,
        priority: 'Med',
        status: 'open',
        assignee: 'Unassigned',
        created: todayIso(),
      });
    },
    cycleMaintStatus(state, action: PayloadAction<number>) {
      const ticket = state.maintTickets.find((t) => t.id === action.payload);
      if (!ticket) return;
      ticket.status = MAINT_STATUS_CYCLE[ticket.status] || 'open';
    },

    // ── Housekeeping ─────────────────────────────────────────────────
    addHk(state, action: PayloadAction<NewHkInput>) {
      state.nextId += 1;
      state.hkTasks.push({
        id: state.nextId,
        task: action.payload.task,
        unit: action.payload.unit,
        type: 'Daily',
        status: 'not_started',
        assignee: 'Unassigned',
        due: tomorrowIso(),
      });
    },
    cycleHkStatus(state, action: PayloadAction<number>) {
      const task = state.hkTasks.find((t) => t.id === action.payload);
      if (!task) return;
      task.status = HK_STATUS_CYCLE[task.status] || 'not_started';
    },

    // ── Tasks ────────────────────────────────────────────────────────
    setTaskForm(state, action: PayloadAction<boolean>) {
      state.taskFormOpen = action.payload;
    },
    addTask(state, action: PayloadAction<NewTaskInput>) {
      state.nextId += 1;
      state.tasks.unshift({ id: state.nextId, ...action.payload, done: false });
      state.taskFormOpen = false;
    },
    toggleTask(state, action: PayloadAction<{ id: number; done: boolean }>) {
      const task = state.tasks.find((t) => t.id === action.payload.id);
      if (task) task.done = action.payload.done;
    },
    deleteTask(state, action: PayloadAction<number>) {
      state.tasks = state.tasks.filter((t) => t.id !== action.payload);
    },

    // ── Tours (inline form only — saving just toasts, no state) ───────
    setTourForm(state, action: PayloadAction<boolean>) {
      state.tourFormOpen = action.payload;
    },
  },
});

export const goldDemoActions = goldDemoSlice.actions;
export default goldDemoSlice.reducer;
