// Role-based navigation, tab titles, and chrome copy for the CommunityLink
// Gold CRM demo. Mirrors the reference NAV / titles / labels objects verbatim.
// Static values only.
import type { GoldRole, GoldTabKey, NavSection } from '../types/goldTypes';

export const NAV: Record<GoldRole, NavSection[]> = {
  director: [
    { sec: 'EXECUTIVE', items: [{ k: 'dashboard', l: 'Executive Dashboard' }, { k: 'occupancy', l: 'Occupancy Overview' }] },
    { sec: 'SALES', items: [{ k: 'leads', l: 'Lead Pipeline' }, { k: 'tours', l: 'Tour Scheduler' }, { k: 'refs', l: 'Referral Sources' }] },
    { sec: 'OPERATIONS', items: [{ k: 'apartments', l: 'Apartment Inventory' }, { k: 'makeready', l: 'Make-Ready Board' }, { k: 'maintenance', l: 'Maintenance Tickets' }, { k: 'housekeeping', l: 'Housekeeping Tasks' }] },
    { sec: 'MANAGEMENT', items: [{ k: 'tasks', l: 'Tasks' }, { k: 'reports', l: 'Reports' }] },
  ],
  admin: [
    { sec: 'MAIN', items: [{ k: 'dashboard', l: 'Dashboard' }, { k: 'leads', l: 'Lead Pipeline' }, { k: 'refs', l: 'Referral Sources' }, { k: 'tours', l: 'Tour Scheduler' }] },
    { sec: 'OPERATIONS', items: [{ k: 'apartments', l: 'Apartment Inventory' }, { k: 'makeready', l: 'Make-Ready Board' }, { k: 'maintenance', l: 'Maintenance' }, { k: 'housekeeping', l: 'Housekeeping' }] },
    { sec: 'TOOLS', items: [{ k: 'tasks', l: 'Tasks' }, { k: 'reports', l: 'Reports' }, { k: 'settings', l: 'Settings' }] },
  ],
  marketer: [
    { sec: 'SALES', items: [{ k: 'dashboard', l: 'Sales Dashboard' }, { k: 'leads', l: 'Lead Pipeline' }, { k: 'tours', l: 'Tours' }, { k: 'refs', l: 'Referral Sources' }, { k: 'tasks', l: 'Tasks' }] },
  ],
  maintenance: [
    { sec: 'MY WORK', items: [{ k: 'dashboard', l: 'My Queue' }, { k: 'maintenance', l: 'Maintenance Tickets' }, { k: 'makeready', l: 'Make-Ready Tasks' }, { k: 'tasks', l: 'Tasks' }] },
  ],
  housekeeping: [
    { sec: 'MY WORK', items: [{ k: 'dashboard', l: 'My Queue' }, { k: 'housekeeping', l: 'Housekeeping Tasks' }, { k: 'makeready', l: 'Make-Ready Clean' }, { k: 'tasks', l: 'Tasks' }] },
  ],
};

export const ROLE_LABELS: Record<GoldRole, string> = {
  director: 'Executive Director',
  admin: 'Administrator',
  marketer: 'Sales Marketer',
  maintenance: 'Maintenance',
  housekeeping: 'Housekeeping',
};

// Role <select> option order (reference roleSelect <option> order).
export const ROLE_OPTIONS: GoldRole[] = ['director', 'admin', 'marketer', 'maintenance', 'housekeeping'];

// The tab a role lands on when selected (reference changeRole() defaults).
export const ROLE_DEFAULT_TAB: Record<GoldRole, GoldTabKey> = {
  director: 'dashboard',
  admin: 'dashboard',
  marketer: 'dashboard',
  maintenance: 'maintenance',
  housekeeping: 'housekeeping',
};

// Topbar title per tab (reference go() titles map).
export const TAB_TITLES: Record<GoldTabKey, string> = {
  dashboard: 'Dashboard',
  occupancy: 'Occupancy Overview',
  leads: 'Lead Pipeline',
  tours: 'Tour Scheduler',
  refs: 'Referral Sources',
  apartments: 'Apartment Inventory',
  makeready: 'Make-Ready Board',
  maintenance: 'Maintenance Tickets',
  housekeeping: 'Housekeeping Tasks',
  tasks: 'Tasks',
  reports: 'Reports Center',
  settings: 'Settings',
};

// Initial topbar title before any navigation (reference HTML hardcodes this).
export const INITIAL_PAGE_TITLE = 'Executive Dashboard';

export const SUBTITLE = 'Sunrise Senior Living — February 2026';
export const PRICING_HREF = '/communitylink/pricing';
