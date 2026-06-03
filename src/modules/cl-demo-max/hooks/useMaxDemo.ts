// Orchestration hook for the Max demo: exposes slice state plus the demo's
// business-logic entry points (modal control, status cycles, toasts, advance
// flows). View components stay presentational.
import { cap } from '@/shared/cl-demo';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { LEAD_STATUS_CYCLE, PR_STAGES, REFERRAL_STAGES } from '../constants/maxData';
import { APT_STATUS_CYCLE, HK_STATUS_CYCLE, MAINT_STATUS_CYCLE } from '../constants/maxStatus';
import { maxDemoActions as A } from '../store/maxDemoSlice';
import type {
  ActivityNote,
  AlertSetting,
  LocBase,
  MaxRole,
  MaxTabKey,
  ModalKey,
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
} from '../types/maxTypes';

export function useMaxDemo() {
  const dispatch = useAppDispatch();
  const state = useAppSelector((s) => s.maxDemo);
  const toast = (m: string, error = false) => dispatch(A.showToast(m, error));

  const actions = {
    setTab: (tab: MaxTabKey) => dispatch(A.setTab(tab)),
    setRole: (role: MaxRole) => dispatch(A.setRole(role)),
    toast,
    hideToast: () => dispatch(A.hideToast()),
    openModal: (key: ModalKey) => dispatch(A.openModalAction(key)),
    closeModal: () => dispatch(A.closeModalAction()),

    // Leads
    cycleLeadStatus: (id: number) => {
      const l = state.leads.find((x) => x.id === id);
      if (!l) return;
      const next = LEAD_STATUS_CYCLE[(LEAD_STATUS_CYCLE.indexOf(l.status as never) + 1) % LEAD_STATUS_CYCLE.length];
      dispatch(A.cycleLeadStatus(id));
      toast(l.name + ' → ' + next);
    },
    addLead: (input: NewLeadInput) => {
      dispatch(A.addLead(input));
      toast('Lead added: ' + input.name + ' — now in pipeline!');
    },

    // Referral sources
    logRefVisit: (id: number) => {
      const r = state.referrals.find((x) => x.id === id);
      if (!r) return;
      dispatch(A.logRefVisit(id));
      toast('Visit logged for ' + r.name);
    },
    addRefSource: (input: NewRefSourceInput) => {
      dispatch(A.addRefSource(input));
      toast('Source added: ' + input.name + ' — now in referral directory!');
    },

    // Apartments
    cycleAptStatus: (id: number) => {
      const a = state.apts.find((x) => x.id === id);
      if (!a) return;
      const next = APT_STATUS_CYCLE[a.status] || 'available';
      dispatch(A.cycleAptStatus(id));
      toast('Unit ' + a.unit + ' → ' + next.replace(/_/g, ' '));
    },
    scheduleMakeReady: (id: number) => {
      const a = state.apts.find((x) => x.id === id);
      if (!a) return;
      dispatch(A.scheduleMakeReady(id));
      dispatch(A.setTab('makeready'));
      toast('Make-ready ticket created for Unit ' + a.unit + '!');
    },
    addApt: (input: NewApartmentInput) => {
      dispatch(A.addApt(input));
      toast('Unit ' + input.unit + ' added! Inventory + ledger updated.');
    },

    // Make-ready
    toggleMrTask: (id: number, idx: number) => { dispatch(A.toggleMrTask({ id, idx })); toast('Task updated!'); },
    advanceMr: (id: number) => {
      const t = state.mrTickets.find((x) => x.id === id);
      if (!t) return;
      dispatch(A.advanceMr(id));
      toast('Progress: ' + Math.min(100, t.pct + 25) + '%');
    },
    completeMr: (id: number) => { dispatch(A.completeMr(id)); toast('Unit marked lease-ready! ✓'); },
    addMr: (input: NewMrInput) => { dispatch(A.addMr(input)); dispatch(A.setTab('makeready')); toast('Make-ready ticket created for Unit ' + input.unit + '!'); },

    // Maintenance
    cycleMaintStatus: (id: number) => {
      const t = state.maintTickets.find((x) => x.id === id);
      if (!t) return;
      const next = MAINT_STATUS_CYCLE[t.status] || 'open';
      dispatch(A.cycleMaintStatus(id));
      toast('Ticket status: ' + cap(next.replace(/_/g, ' ')));
    },
    addMaint: (input: NewMaintInput) => {
      const num = 'M-' + (state.maintTickets.length + 1).toString().padStart(3, '0');
      dispatch(A.addMaint(input));
      dispatch(A.setTab('maintenance'));
      toast('Ticket ' + num + ' created! Maintenance board updated.');
    },

    // Housekeeping / assign task
    cycleHkStatus: (id: number) => {
      const t = state.hkTasks.find((x) => x.id === id);
      if (!t) return;
      const next = HK_STATUS_CYCLE[t.status] || 'not_started';
      dispatch(A.cycleHkStatus(id));
      toast(next === 'completed' ? 'Task complete! ✓' : 'Status updated.');
    },
    addAssignTask: (p: { task: string; assignee: string; type: string; priority: string; unit: string; due: string }) => {
      dispatch(A.addAssignTask(p));
      dispatch(A.setTab(state.activeTab === 'housekeeping' ? 'housekeeping' : 'tasks'));
      toast('Task assigned to ' + p.assignee + '!');
    },

    // Tasks
    addTask: (input: NewTaskInput) => { dispatch(A.addTask(input)); toast('Task added!'); },
    toggleTask: (id: number, done: boolean) => { dispatch(A.toggleTask({ id, done })); toast(done ? 'Done!' : 'Reopened.'); },
    deleteTask: (id: number) => { dispatch(A.deleteTask(id)); toast('Removed.'); },

    // Referral pipeline
    addPaidReferral: (p: { name: string; source: string; type: 'Paid' | 'Organic'; fee: number; care: string }) => {
      dispatch(A.addPaidReferral(p));
      toast('Referral added: ' + p.name);
    },
    advancePaidReferral: (id: number) => {
      const r = state.paidReferrals.find((x) => x.id === id);
      if (!r) return;
      if (r.stage === 'Moved In') { toast(r.name + ' already moved in!'); return; }
      if (r.stage === 'Lost') { toast(r.name + ' is marked Lost — re-engage to reopen.'); return; }
      const idx = REFERRAL_STAGES.indexOf(r.stage);
      if (idx < REFERRAL_STAGES.length - 2) {
        dispatch(A.advancePaidReferral({ id }));
        toast(r.name + ' advanced to: ' + REFERRAL_STAGES[idx + 1]);
      } else {
        const reason = window.prompt('Mark as Lost — reason (Not interested / Chose competitor / Pricing / Medical decline / No response / Deceased / Duplicate / Other):', 'Not interested');
        if (reason) { dispatch(A.advancePaidReferral({ id, lostReason: reason })); toast(r.name + ' marked Lost.'); }
      }
    },
    viewRef: (id: number) => {
      const r = state.paidReferrals.find((x) => x.id === id);
      if (!r) return;
      window.alert('REFERRAL DETAIL\nName: ' + r.name + '\nSource: ' + r.source + ' (' + r.type + ')\nStage: ' + r.stage + '\nCare Level: ' + r.care + '\nFee: $' + r.fee + ' | Status: ' + r.feeStatus + '\nAssigned: ' + r.assigned + '\nPhone: ' + (r.phone || '—') + '\nTour: ' + (r.tourDate || 'Not scheduled') + '\nTarget Move-In: ' + (r.moveInTarget || 'TBD') + (r.lostReason ? '\nLost Reason: ' + r.lostReason : '') + '\n\nNotes: ' + r.notes);
    },

    // Paid referral portal
    addPaidRefPortal: (input: NewPaidRefInput) => { dispatch(A.addPaidRefPortal(input)); toast('Paid referral added: ' + input.prospect_name + ' — Team alert sent (Demo)'); },
    advancePaidRefPortal: (id: string) => {
      const r = state.paidRefsPortal.find((x) => x.id === id);
      if (!r) return;
      if (r.stage === 'Moved In') { toast(r.prospect_name + ' already moved in!'); return; }
      const idx = PR_STAGES.indexOf(r.stage);
      if (idx < PR_STAGES.length - 2) {
        dispatch(A.advancePaidRefPortal({ id }));
        toast(r.prospect_name + ' advanced to: ' + PR_STAGES[idx + 1]);
      } else {
        const reason = window.prompt('Mark as Lost — reason:', 'Not interested');
        if (reason) { dispatch(A.advancePaidRefPortal({ id, lostReason: reason })); toast(r.prospect_name + ' marked Lost.'); }
      }
    },
    viewPaidRefPortal: (id: string) => {
      const r = state.paidRefsPortal.find((x) => x.id === id);
      if (!r) return;
      window.alert('REFERRAL DETAIL\nName: ' + r.prospect_name + '\nSource: ' + r.source_name + '\nCare: ' + r.care_level + '\nBudget: ' + r.budget_range + '\nTimeline: ' + r.move_in_timeframe + '\nUrgency: ' + (r.urgency || '—').toUpperCase() + '\nStage: ' + r.stage + '\nFee: $' + (r.referral_fee || 0) + ' (' + r.fee_status + ')\nContact: ' + r.prospect_phone + '\n\nSource Notes:\n' + r.source_notes);
    },

    // Concessions
    addConcession: (input: NewConcessionInput) => { dispatch(A.addConcession(input)); toast('Concession request submitted for approval!'); },
    decideConcession: (id: string, decision: 'approved' | 'denied') => {
      dispatch(A.decideConcession({ id, decision }));
      toast(decision === 'approved' ? 'Concession approved! Financial impact recorded.' : 'Concession denied.');
    },

    // Competitors
    addCompetitor: (input: NewCompetitorInput) => { dispatch(A.addCompetitor(input)); toast('Competitor added!'); },

    // LOC
    saveLocRates: (base: LocBase) => { dispatch(A.saveLocRates(base)); toast('LOC rates saved! Calculator updated.'); },

    // Mileage
    addMileageLog: (input: NewMileageInput, hasReceipt: boolean) => {
      dispatch(A.addMileageLog(input));
      toast('✅ Mileage logged' + (hasReceipt ? ' with receipt' : '') + '! Reimbursement: $' + input.reimbursement.toFixed(2));
    },

    // Gift
    addGiftLog: (input: NewGiftInput, withinLimit: boolean) => {
      dispatch(A.addGiftLog(input));
      toast(withinLimit ? 'Gift logged — within compliance.' : 'Gift logged — OVER the $' + state.giftLimit + ' limit!');
    },

    // Alerts / Fin settings
    saveAlert: (key: string, setting: AlertSetting) => { dispatch(A.saveAlert({ key, setting })); toast('Alert setting saved: ' + key + ' is now ' + (setting.enabled ? 'ON' : 'OFF') + ' via ' + setting.channel); },
    saveFinSetting: (key: string, value: string) => {
      const old = state.finSettings[key];
      dispatch(A.saveFinSetting({ key, value }));
      toast('✅ ' + key + ' updated: $' + old + ' to $' + value + ' (Demo)');
    },

    // Notes
    addNote: (note: ActivityNote) => { dispatch(A.addNote(note)); toast('📝 Note saved to activity timeline!'); },
    addAircallNote: (note: ActivityNote, icon: string) => { dispatch(A.addNote(note)); toast(icon + ' Activity logged to Notes tab!'); },
  };

  return { ...state, actions };
}
