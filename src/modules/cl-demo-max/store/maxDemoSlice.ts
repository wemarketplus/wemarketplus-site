// Redux slice holding the Max demo's mutable in-memory state. Mirrors the
// reference's module-level arrays + nextId counter, plus UI state (active tab,
// role, page title, open modal, toast). All mutations route through here.
import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ToastState } from '@/shared/cl-demo';
import {
  DEMO_GIFT_LIMIT,
  DEMO_MILEAGE_RATE,
  LEAD_STATUS_CYCLE,
  REFERRAL_STAGES,
  PR_STAGES,
  SEED_ALERTS,
  SEED_APTS,
  SEED_COMPETITORS,
  SEED_CONCESSIONS,
  SEED_FIN_SETTINGS,
  SEED_GIFT_LOGS,
  SEED_HK_TASKS,
  SEED_LEAK_ITEMS,
  SEED_LEADS,
  SEED_LOC_BASE,
  SEED_MAINT_TICKETS,
  SEED_MILEAGE_LOGS,
  SEED_MR_TICKETS,
  SEED_NEXT_ID,
  SEED_NOTES,
  SEED_PAID_REFERRALS,
  SEED_PAID_REFS_PORTAL,
  SEED_REFERRALS,
  SEED_REVENUE_MONTHS,
  SEED_TASKS,
} from '../constants/maxData';
import { INITIAL_PAGE_TITLE, ROLE_DEFAULT_TAB, ROLE_TITLE, TAB_TITLES } from '../constants/maxNav';
import { APT_STATUS_CYCLE, HK_STATUS_CYCLE, MAINT_STATUS_CYCLE } from '../constants/maxStatus';
import type {
  ActivityNote,
  AlertSetting,
  Apartment,
  Competitor,
  Concession,
  GiftLog,
  HkTask,
  Lead,
  LeakItem,
  LocBase,
  MaintTicket,
  MaxRole,
  MaxTabKey,
  MileageLog,
  ModalKey,
  MrTicket,
  NewApartmentInput,
  NewCompetitorInput,
  NewConcessionInput,
  NewGiftInput,
  NewLeadInput,
  NewMaintInput,
  NewMileageInput,
  NewMrInput,
  NewPaidRefInput,
  NewRefSourceInput,
  NewTaskInput,
  PaidRefPortal,
  PaidReferral,
  RefSource,
  RevenueMonth,
  Task,
} from '../types/maxTypes';

interface MaxDemoState {
  leads: Lead[];
  apts: Apartment[];
  mrTickets: MrTicket[];
  maintTickets: MaintTicket[];
  hkTasks: HkTask[];
  referrals: RefSource[];
  tasks: Task[];
  notes: ActivityNote[];
  paidReferrals: PaidReferral[];
  paidRefsPortal: PaidRefPortal[];
  revenueMonths: RevenueMonth[];
  concessions: Concession[];
  competitors: Competitor[];
  leakItems: LeakItem[];
  locBase: LocBase;
  mileageLogs: MileageLog[];
  giftLogs: GiftLog[];
  giftLimit: number;
  mileageRate: number;
  alerts: Record<string, AlertSetting>;
  finSettings: Record<string, string>;
  role: MaxRole;
  activeTab: MaxTabKey;
  pageTitle: string;
  nextId: number;
  openModal: ModalKey | null;
  toast: ToastState | null;
}

const initialState: MaxDemoState = {
  leads: SEED_LEADS.map((l) => ({ ...l })),
  apts: SEED_APTS.map((a) => ({ ...a })),
  mrTickets: SEED_MR_TICKETS.map((t) => ({ ...t, tasks: [...t.tasks] })),
  maintTickets: SEED_MAINT_TICKETS.map((t) => ({ ...t })),
  hkTasks: SEED_HK_TASKS.map((t) => ({ ...t })),
  referrals: SEED_REFERRALS.map((r) => ({ ...r })),
  tasks: SEED_TASKS.map((t) => ({ ...t })),
  notes: SEED_NOTES.map((n) => ({ ...n })),
  paidReferrals: SEED_PAID_REFERRALS.map((r) => ({ ...r })),
  paidRefsPortal: SEED_PAID_REFS_PORTAL.map((r) => ({ ...r })),
  revenueMonths: SEED_REVENUE_MONTHS.map((m) => ({ ...m })),
  concessions: SEED_CONCESSIONS.map((c) => ({ ...c })),
  competitors: SEED_COMPETITORS.map((c) => ({ ...c })),
  leakItems: SEED_LEAK_ITEMS.map((i) => ({ ...i })),
  locBase: { ...SEED_LOC_BASE },
  mileageLogs: SEED_MILEAGE_LOGS.map((l) => ({ ...l })),
  giftLogs: SEED_GIFT_LOGS.map((l) => ({ ...l })),
  giftLimit: DEMO_GIFT_LIMIT,
  mileageRate: DEMO_MILEAGE_RATE,
  alerts: JSON.parse(JSON.stringify(SEED_ALERTS)),
  finSettings: { ...SEED_FIN_SETTINGS },
  role: 'director',
  activeTab: 'dashboard',
  pageTitle: INITIAL_PAGE_TITLE,
  nextId: SEED_NEXT_ID,
  openModal: null,
  toast: null,
};

function todayIso(): string {
  return new Date().toISOString().split('T')[0];
}

const slice = createSlice({
  name: 'maxDemo',
  initialState,
  reducers: {
    setTab(state, action: PayloadAction<MaxTabKey>) {
      state.activeTab = action.payload;
      state.pageTitle = TAB_TITLES[action.payload];
    },
    setRole(state, action: PayloadAction<MaxRole>) {
      state.role = action.payload;
      state.activeTab = ROLE_DEFAULT_TAB[action.payload];
      state.pageTitle = ROLE_TITLE[action.payload] || 'Dashboard';
    },
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
    openModalAction(state, action: PayloadAction<ModalKey>) {
      state.openModal = action.payload;
    },
    closeModalAction(state) {
      state.openModal = null;
    },

    // ── Leads ──
    addLead(state, action: PayloadAction<NewLeadInput>) {
      state.nextId += 1;
      state.leads.unshift({ id: state.nextId, ...action.payload });
      state.nextId += 1;
      state.notes.unshift({
        id: state.nextId,
        type: 'manual',
        comm_type: 'manual',
        contact_name: action.payload.name,
        summary: 'New lead added: ' + action.payload.name + ' (' + action.payload.care + ') — Source: ' + action.payload.source,
        outcome: 'Lead created',
        next_step: action.payload.status === 'Tour Scheduled' ? 'Prepare for tour' : 'Follow up within 48 hours',
        follow_up_date: action.payload.fu,
        created_at: new Date().toISOString(),
        user_name: 'Admin',
      });
      state.openModal = null;
    },
    cycleLeadStatus(state, action: PayloadAction<number>) {
      const lead = state.leads.find((l) => l.id === action.payload);
      if (!lead) return;
      const idx = LEAD_STATUS_CYCLE.indexOf(lead.status as never);
      lead.status = LEAD_STATUS_CYCLE[(idx + 1) % LEAD_STATUS_CYCLE.length];
    },

    // ── Referral sources ──
    addRefSource(state, action: PayloadAction<NewRefSourceInput>) {
      state.nextId += 1;
      state.referrals.push({ id: state.nextId, name: action.payload.name, org: action.payload.org, type: action.payload.type, leads: 0, last: todayIso() });
      state.openModal = null;
    },
    logRefVisit(state, action: PayloadAction<number>) {
      const r = state.referrals.find((x) => x.id === action.payload);
      if (!r) return;
      r.leads += 1;
      r.last = todayIso();
    },

    // ── Apartments ──
    addApt(state, action: PayloadAction<NewApartmentInput>) {
      state.nextId += 1;
      state.apts.push({ id: state.nextId, ...action.payload, mrTasks: 0 });
      if (action.payload.rate > 0) state.revenueMonths.forEach((m) => { m.bud += action.payload.rate; });
      state.openModal = null;
    },
    cycleAptStatus(state, action: PayloadAction<number>) {
      const a = state.apts.find((x) => x.id === action.payload);
      if (!a) return;
      a.status = (APT_STATUS_CYCLE[a.status] as Apartment['status']) || 'available';
    },
    scheduleMakeReady(state, action: PayloadAction<number>) {
      const a = state.apts.find((x) => x.id === action.payload);
      if (!a) return;
      a.status = 'make_ready';
      a.mrTasks = 5;
      state.nextId += 1;
      state.mrTickets.push({ id: state.nextId, unit: a.unit, type: a.type, moveout: '2026-02-28', target: '2026-03-10', pct: 0, tasks: ['Trash out', 'Locks changed', 'Paint', 'Cleaning', 'Inspection'], assignee: 'TBD' });
    },

    // ── Make-ready ──
    addMr(state, action: PayloadAction<NewMrInput>) {
      state.nextId += 1;
      state.mrTickets.unshift({ id: state.nextId, unit: action.payload.unit, type: 'Unit Turn', moveout: action.payload.moveout || 'TBD', target: action.payload.target || 'TBD', pct: 0, tasks: action.payload.tasks.length ? action.payload.tasks : ['Trash out', 'Cleaning', 'Inspection'], assignee: action.payload.assignee || 'TBD' });
      state.openModal = null;
    },
    toggleMrTask(state, action: PayloadAction<{ id: number; idx: number }>) {
      const t = state.mrTickets.find((x) => x.id === action.payload.id);
      if (!t) return;
      const task = t.tasks[action.payload.idx];
      t.tasks[action.payload.idx] = task.startsWith('done:') ? task.slice(5) : 'done:' + task;
      const done = t.tasks.filter((x) => x.startsWith('done:')).length;
      t.pct = Math.round((done / t.tasks.length) * 100);
    },
    advanceMr(state, action: PayloadAction<number>) {
      const t = state.mrTickets.find((x) => x.id === action.payload);
      if (t) t.pct = Math.min(100, t.pct + 25);
    },
    completeMr(state, action: PayloadAction<number>) {
      const t = state.mrTickets.find((x) => x.id === action.payload);
      if (!t) return;
      t.pct = 100;
      t.tasks = t.tasks.map((x) => (x.startsWith('done:') ? x : 'done:' + x));
    },

    // ── Maintenance ──
    addMaint(state, action: PayloadAction<NewMaintInput>) {
      state.nextId += 1;
      state.maintTickets.unshift({ id: state.nextId, ticket: 'M-' + (state.maintTickets.length + 1).toString().padStart(3, '0'), unit: action.payload.unit, resident: '', issue: action.payload.issue, priority: action.payload.priority, status: action.payload.status, assignee: action.payload.assignee, created: todayIso() });
      state.openModal = null;
    },
    cycleMaintStatus(state, action: PayloadAction<number>) {
      const t = state.maintTickets.find((x) => x.id === action.payload);
      if (!t) return;
      t.status = MAINT_STATUS_CYCLE[t.status] || 'open';
    },

    // ── Housekeeping / assign task ──
    addAssignTask(state, action: PayloadAction<{ task: string; assignee: string; type: string; priority: string; unit: string; due: string }>) {
      const p = action.payload;
      state.nextId += 1;
      state.hkTasks.unshift({ id: state.nextId, task: p.task, unit: p.unit, type: p.type, status: 'not_started', assignee: p.assignee, due: p.due });
      state.nextId += 1;
      state.tasks.unshift({ id: state.nextId, title: p.task, due: p.due, priority: p.priority, done: false });
      state.openModal = null;
    },
    cycleHkStatus(state, action: PayloadAction<number>) {
      const t = state.hkTasks.find((x) => x.id === action.payload);
      if (!t) return;
      t.status = HK_STATUS_CYCLE[t.status] || 'not_started';
    },

    // ── Tasks list ──
    addTask(state, action: PayloadAction<NewTaskInput>) {
      state.nextId += 1;
      state.tasks.unshift({ id: state.nextId, ...action.payload, done: false });
    },
    toggleTask(state, action: PayloadAction<{ id: number; done: boolean }>) {
      const t = state.tasks.find((x) => x.id === action.payload.id);
      if (t) t.done = action.payload.done;
    },
    deleteTask(state, action: PayloadAction<number>) {
      state.tasks = state.tasks.filter((t) => t.id !== action.payload);
    },

    // ── Referral pipeline (PAID_REFERRALS) ──
    addPaidReferral(state, action: PayloadAction<{ name: string; source: string; type: 'Paid' | 'Organic'; fee: number; care: string }>) {
      const p = action.payload;
      state.nextId += 1;
      state.paidReferrals.unshift({ id: state.nextId, source: p.source, partner: p.source.split(' ')[0], type: p.type, fee: p.fee, feeStatus: p.fee > 0 ? 'Pending' : 'N/A', name: p.name, care: p.care, stage: 'New Referral', urgency: 'Medium', assigned: 'Sarah M.', phone: '', tourDate: '', moveInTarget: '', notes: '', lostReason: '', created: todayIso() });
    },
    advancePaidReferral(state, action: PayloadAction<{ id: number; lostReason?: string }>) {
      const r = state.paidReferrals.find((x) => x.id === action.payload.id);
      if (!r) return;
      const idx = REFERRAL_STAGES.indexOf(r.stage);
      if (r.stage === 'Moved In' || r.stage === 'Lost') return;
      if (idx < REFERRAL_STAGES.length - 2) {
        r.stage = REFERRAL_STAGES[idx + 1];
        if (r.stage === 'Moved In' && r.feeStatus === 'Pending') r.feeStatus = 'Paid';
      } else if (action.payload.lostReason) {
        r.stage = 'Lost';
        r.lostReason = action.payload.lostReason;
        r.feeStatus = 'N/A';
      }
    },

    // ── Paid referral portal (DEMO_PAID_REFS) ──
    addPaidRefPortal(state, action: PayloadAction<NewPaidRefInput>) {
      const p = action.payload;
      state.nextId += 1;
      state.paidRefsPortal.unshift({ id: 'pr' + state.nextId, prospect_name: p.prospect_name, source_name: p.source_name, prospect_phone: '', care_level: 'Assisted Living', budget_range: '—', move_in_timeframe: '60 days', urgency: 'warm', referral_fee: p.referral_fee, fee_status: 'pending', stage: 'New Referral', source_contact: '', source_notes: '', received_at: new Date().toISOString(), assigned_name: 'Sarah M.' });
    },
    advancePaidRefPortal(state, action: PayloadAction<{ id: string; lostReason?: string }>) {
      const r = state.paidRefsPortal.find((x) => x.id === action.payload.id);
      if (!r) return;
      const idx = PR_STAGES.indexOf(r.stage);
      if (r.stage === 'Moved In') return;
      if (idx < PR_STAGES.length - 2) {
        r.stage = PR_STAGES[idx + 1];
        if (r.stage === 'Moved In' && r.fee_status === 'pending') r.fee_status = 'paid';
      } else if (action.payload.lostReason) {
        r.stage = 'Lost';
        r.fee_status = 'na';
      }
    },

    // ── Concessions ──
    addConcession(state, action: PayloadAction<NewConcessionInput>) {
      state.concessions.unshift({ id: 'C-00' + (state.concessions.length + 4), unit: action.payload.unit || 'TBD', resident: action.payload.resident, type: action.payload.type, value: action.payload.value, status: 'pending', by: 'Demo User' });
    },
    decideConcession(state, action: PayloadAction<{ id: string; decision: 'approved' | 'denied' }>) {
      const c = state.concessions.find((x) => x.id === action.payload.id);
      if (c) c.status = action.payload.decision;
    },

    // ── Competitors ──
    addCompetitor(state, action: PayloadAction<NewCompetitorInput>) {
      state.competitors.unshift({ ...action.payload });
    },

    // ── LOC ──
    saveLocRates(state, action: PayloadAction<LocBase>) {
      state.locBase = { ...action.payload };
    },

    // ── Mileage ──
    addMileageLog(state, action: PayloadAction<NewMileageInput>) {
      state.mileageLogs.unshift({ id: 'ml' + Date.now(), ...action.payload, status: 'pending', submitted_by: 'Sarah M.' });
    },

    // ── Gift ──
    addGiftLog(state, action: PayloadAction<NewGiftInput>) {
      state.giftLogs.unshift({ id: 'g' + Date.now(), ...action.payload, logged_by_name: 'You' });
    },

    // ── Alert settings ──
    saveAlert(state, action: PayloadAction<{ key: string; setting: AlertSetting }>) {
      state.alerts[action.payload.key] = action.payload.setting;
    },

    // ── Financial settings ──
    saveFinSetting(state, action: PayloadAction<{ key: string; value: string }>) {
      state.finSettings[action.payload.key] = action.payload.value;
      if (action.payload.key === 'gift_gratuity_limit') state.giftLimit = parseFloat(action.payload.value) || state.giftLimit;
      if (action.payload.key === 'mileage_rate') state.mileageRate = parseFloat(action.payload.value) || state.mileageRate;
    },

    // ── Notes ──
    addNote(state, action: PayloadAction<ActivityNote>) {
      state.nextId += 1;
      state.notes.unshift({ ...action.payload, id: state.nextId });
    },
  },
});

export const maxDemoActions = slice.actions;
export default slice.reducer;
