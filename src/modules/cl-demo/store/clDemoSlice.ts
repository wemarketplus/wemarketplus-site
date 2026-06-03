// Redux slice holding the demo's mutable in-memory state. Mirrors the
// reference's module-level arrays + nextId counter, plus UI state (active tab,
// role, lead modal target, inline form toggles, toast). All mutations route
// through these reducers so every tab reads a single source of truth.
import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import { todayIso } from '@/shared/cl-demo';
import {
  COMMUNITY_DEFAULTS,
  SEED_LEADS,
  SEED_MILEAGE,
  SEED_NEXT_ID,
  SEED_NOTES,
  SEED_OUTREACH,
  SEED_REFERRALS,
  SEED_TASKS,
  SEED_TOURS,
} from '../constants/clDemoData';
import { NAV } from '../constants/clDemoNav';
import type {
  DemoRole,
  Lead,
  LeadEdit,
  MileageEntry,
  NewLeadInput,
  NewMileageInput,
  NewNoteInput,
  NewOutreachInput,
  NewReferralInput,
  NewTaskInput,
  NewTourInput,
  Note,
  OutreachEntry,
  Referral,
  TabKey,
  Task,
  Tour,
  ToastState,
} from '../types/clDemoTypes';

interface ClDemoState {
  leads: Lead[];
  referrals: Referral[];
  tasks: Task[];
  tours: Tour[];
  outreach: OutreachEntry[];
  mileage: MileageEntry[];
  notes: Note[];
  role: DemoRole;
  activeTab: TabKey;
  nextId: number;
  // Lead-detail modal target (null = closed).
  leadModalId: number | null;
  // Inline form toggles for the tours / tasks tabs.
  tourFormOpen: boolean;
  taskFormOpen: boolean;
  toast: ToastState | null;
}

const initialState: ClDemoState = {
  leads: SEED_LEADS.map((l) => ({ ...l })),
  referrals: SEED_REFERRALS.map((r) => ({ ...r })),
  tasks: SEED_TASKS.map((t) => ({ ...t })),
  tours: SEED_TOURS.map((t) => ({ ...t })),
  outreach: SEED_OUTREACH.map((o) => ({ ...o })),
  mileage: SEED_MILEAGE.map((m) => ({ ...m })),
  notes: SEED_NOTES.map((n) => ({ ...n })),
  role: 'admin',
  activeTab: 'dashboard',
  nextId: SEED_NEXT_ID,
  leadModalId: null,
  tourFormOpen: false,
  taskFormOpen: false,
  toast: null,
};

const clDemoSlice = createSlice({
  name: 'clDemo',
  initialState,
  reducers: {
    setTab(state, action: PayloadAction<TabKey>) {
      state.activeTab = action.payload;
      // Reset transient inline forms when navigating away.
      state.tourFormOpen = false;
      state.taskFormOpen = false;
    },
    setRole(state, action: PayloadAction<DemoRole>) {
      state.role = action.payload;
      const allowed = NAV[action.payload].flatMap((g) => g.items.map((i) => i.k));
      if (!allowed.includes(state.activeTab)) state.activeTab = 'dashboard';
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
      state.leads.unshift({ id: state.nextId, ...action.payload });
    },
    saveLeadEdit(state, action: PayloadAction<LeadEdit>) {
      const lead = state.leads.find((l) => l.id === action.payload.id);
      if (!lead) return;
      lead.status = action.payload.status;
      lead.urgency = action.payload.urgency;
      lead.fu = action.payload.fu;
      lead.source = action.payload.source;
      lead.notes = action.payload.notes;
    },
    deleteLead(state, action: PayloadAction<number>) {
      state.leads = state.leads.filter((l) => l.id !== action.payload);
    },
    openLead(state, action: PayloadAction<number>) {
      state.leadModalId = action.payload;
    },
    closeLead(state) {
      state.leadModalId = null;
    },

    // ── Referrals ────────────────────────────────────────────────────
    addReferral(state, action: PayloadAction<NewReferralInput>) {
      state.nextId += 1;
      state.referrals.push({ id: state.nextId, ...action.payload, leads: 0, last: '—' });
    },
    logRefVisit(state, action: PayloadAction<number>) {
      const ref = state.referrals.find((r) => r.id === action.payload);
      if (!ref) return;
      ref.last = todayIso();
      ref.leads += 1;
      state.nextId += 1;
      state.outreach.unshift({
        id: state.nextId,
        date: ref.last,
        location: ref.org,
        contact: ref.name,
        type: 'Referral Visit',
        miles: 0,
        notes: 'Visit logged.',
      });
    },
    deleteRef(state, action: PayloadAction<number>) {
      state.referrals = state.referrals.filter((r) => r.id !== action.payload);
    },

    // ── Tours ────────────────────────────────────────────────────────
    setTourForm(state, action: PayloadAction<boolean>) {
      state.tourFormOpen = action.payload;
    },
    addTour(state, action: PayloadAction<NewTourInput>) {
      state.nextId += 1;
      state.tours.push({ id: state.nextId, ...action.payload, status: 'Confirmed' });
      state.tourFormOpen = false;
    },
    toggleTourStatus(state, action: PayloadAction<number>) {
      const tour = state.tours.find((t) => t.id === action.payload);
      if (!tour) return;
      tour.status = tour.status === 'Confirmed' ? 'Pending' : 'Confirmed';
    },

    // ── GPS / Outreach ───────────────────────────────────────────────
    addOutreach(state, action: PayloadAction<NewOutreachInput>) {
      state.nextId += 1;
      state.outreach.unshift({ id: state.nextId, ...action.payload });
      if (action.payload.miles > 0) {
        state.nextId += 1;
        state.mileage.unshift({
          id: state.nextId,
          date: action.payload.date,
          from: COMMUNITY_DEFAULTS.name,
          to: action.payload.location,
          miles: action.payload.miles,
          purpose: action.payload.type,
        });
      }
    },

    // ── Mileage ──────────────────────────────────────────────────────
    addMileage(state, action: PayloadAction<NewMileageInput>) {
      state.nextId += 1;
      state.mileage.unshift({ id: state.nextId, ...action.payload });
    },
    deleteMileage(state, action: PayloadAction<number>) {
      state.mileage = state.mileage.filter((m) => m.id !== action.payload);
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

    // ── Notes ────────────────────────────────────────────────────────
    addNote(state, action: PayloadAction<NewNoteInput>) {
      state.nextId += 1;
      state.notes.unshift({ id: state.nextId, ...action.payload });
    },
  },
});

export const clDemoActions = clDemoSlice.actions;
export default clDemoSlice.reducer;
