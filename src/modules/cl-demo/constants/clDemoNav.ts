// Navigation config, tab titles, and visual maps for the CommunityLink Pro
// CRM demo. Static values only — mirrors the reference's NAV / titles /
// stageColors objects.
import type { DemoRole, LeadStatus, NavSection, TabKey } from '../types/clDemoTypes';

export const NAV: Record<DemoRole, NavSection[]> = {
  admin: [
    { sec: 'MAIN', items: [{ k: 'dashboard', l: 'Dashboard' }, { k: 'addlead', l: 'Add Lead' }, { k: 'leads', l: 'Lead Pipeline' }, { k: 'refs', l: 'Referral Sources' }, { k: 'addref', l: 'Add Referral Source' }] },
    { sec: 'OUTREACH', items: [{ k: 'tours', l: 'Tour Scheduler' }, { k: 'gps', l: 'GPS Check-In' }, { k: 'mileage', l: 'Mileage Tracker' }, { k: 'outreach', l: 'Outreach Log' }] },
    { sec: 'TOOLS', items: [{ k: 'tasks', l: 'Task Manager' }, { k: 'notes', l: 'Activity Notes' }, { k: 'ai', l: 'AI Sales Assistant' }, { k: 'reports', l: 'Reports Center' }, { k: 'settings', l: 'Settings' }] },
  ],
  marketer: [
    { sec: 'MY WORK', items: [{ k: 'dashboard', l: 'My Dashboard' }, { k: 'addlead', l: 'Add Lead' }, { k: 'leads', l: 'My Leads' }, { k: 'tours', l: 'Tours' }, { k: 'gps', l: 'GPS Check-In' }, { k: 'mileage', l: 'Mileage' }, { k: 'tasks', l: 'My Tasks' }, { k: 'notes', l: 'Notes' }, { k: 'ai', l: 'AI Assistant' }] },
    { sec: 'SOURCES', items: [{ k: 'refs', l: 'Referral Sources' }, { k: 'outreach', l: 'Outreach Log' }] },
  ],
};

export const ROLE_LABELS: Record<DemoRole, string> = {
  admin: 'Administrator',
  marketer: 'Sales Marketer',
};

export const TAB_TITLES: Record<TabKey, string> = {
  dashboard: 'Sales Dashboard',
  addlead: 'Add New Lead',
  leads: 'Lead Pipeline',
  refs: 'Referral Sources',
  addref: 'Add Referral Source',
  tours: 'Tour Scheduler',
  gps: 'GPS Check-In',
  mileage: 'Mileage Tracker',
  outreach: 'Outreach Log',
  tasks: 'Task Manager',
  notes: 'Activity Notes',
  ai: 'AI Sales Assistant',
  reports: 'Reports Center',
  settings: 'Settings',
};

// Pipeline Overview stages + their accent colors (verbatim from the reference).
export const STAGES: LeadStatus[] = ['Inquiry', 'Follow-up', 'Tour Scheduled', 'Proposal Sent', 'Decision Pending', 'Move-In'];

export const STAGE_COLORS: Record<string, string> = {
  Inquiry: '#3d9ee8',
  'Follow-up': '#a78bfa',
  'Tour Scheduled': '#f59e0b',
  'Proposal Sent': '#f87171',
  'Decision Pending': '#ec4899',
  'Move-In': '#4fc87a',
};

// Leads-by-source bar chart palette (reports tab).
export const SOURCE_CHART_COLORS = ['#f59e0b', '#3d9ee8', '#4fc87a', '#a78bfa', '#f87171'];

// IRS mileage reimbursement rate (2026), used across mileage + dashboard.
export const IRS_RATE = 0.67;

export const PRICING_HREF = '/communitylink/pricing';
export const SUBTITLE = 'Sunrise Senior Living — February 2026';
