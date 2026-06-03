// Role-based navigation, tab titles, and chrome copy for the CommunityLink Max
// CRM demo. Mirrors the reference NAV / titles / labels objects verbatim.
import type { MaxRole, MaxTabKey, NavSection } from '../types/maxTypes';

export const NAV: Record<MaxRole, NavSection[]> = {
  owner: [
    { sec: 'EXECUTIVE', items: [{ k: 'dashboard', l: 'Portfolio Dashboard' }, { k: 'occupancy', l: 'Occupancy Overview' }] },
    { sec: 'SALES', items: [{ k: 'leads', l: 'Lead Pipeline' }, { k: 'referrals', l: 'Referral Pipeline' }, { k: 'paidrefs', l: '💰 Paid Referral Portal' }, { k: 'tours', l: 'Tour Scheduler' }, { k: 'refs', l: 'Referral Sources' }] },
    { sec: 'OPERATIONS', items: [{ k: 'apartments', l: 'Apartment Inventory' }, { k: 'makeready', l: 'Make-Ready Board' }, { k: 'maintenance', l: 'Maintenance Tickets' }, { k: 'housekeeping', l: 'Housekeeping Tasks' }] },
    { sec: 'FINANCIAL', items: [{ k: 'ledger', l: 'Financial Ledger' }, { k: 'revenue', l: 'Revenue Leakage' }, { k: 'concessions', l: 'Concession Approvals' }, { k: 'loc', l: 'LOC Calculator' }, { k: 'competitors', l: 'Competitor Intel' }] },
    { sec: 'ACTIVITY', items: [{ k: 'notes', l: '📋 Activity Notes' }, { k: 'tasks', l: 'Tasks' }, { k: 'aircall', l: '☎️ Aircall — Call · Text · Email' }] },
    { sec: 'MANAGEMENT', items: [{ k: 'reports', l: 'Reports' }, { k: 'settings', l: 'Settings' }] },
  ],
  director: [
    { sec: 'EXECUTIVE', items: [{ k: 'dashboard', l: 'Executive Dashboard' }, { k: 'occupancy', l: 'Occupancy Overview' }] },
    { sec: 'SALES', items: [{ k: 'leads', l: 'Lead Pipeline' }, { k: 'referrals', l: 'Referral Pipeline' }, { k: 'paidrefs', l: '💰 Paid Referral Portal' }, { k: 'tours', l: 'Tour Scheduler' }, { k: 'refs', l: 'Referral Sources' }] },
    { sec: 'OPERATIONS', items: [{ k: 'apartments', l: 'Apartment Inventory' }, { k: 'makeready', l: 'Make-Ready Board' }, { k: 'maintenance', l: 'Maintenance Tickets' }, { k: 'housekeeping', l: 'Housekeeping Tasks' }] },
    { sec: 'FINANCIAL', items: [{ k: 'ledger', l: 'Financial Ledger' }, { k: 'revenue', l: 'Revenue Leakage' }, { k: 'concessions', l: 'Concession Approvals' }, { k: 'loc', l: 'LOC Calculator' }] },
    { sec: 'ACTIVITY', items: [{ k: 'notes', l: '📋 Activity Notes' }, { k: 'mileage', l: '🚗 Mileage & Expenses' }, { k: 'tasks', l: 'Tasks' }, { k: 'gift', l: '🎁 Gift & Gratuity' }, { k: 'aircall', l: '☎️ Aircall — Call · Text · Email' }] },
    { sec: 'MANAGEMENT', items: [{ k: 'reports', l: 'Reports' }] },
  ],
  admin: [
    { sec: 'MAIN', items: [{ k: 'dashboard', l: 'Dashboard' }, { k: 'occupancy', l: 'Occupancy Overview' }] },
    { sec: 'SALES', items: [{ k: 'leads', l: 'Lead Pipeline' }, { k: 'referrals', l: 'Referral Pipeline' }, { k: 'paidrefs', l: '💰 Paid Referral Portal' }, { k: 'refs', l: 'Referral Sources' }, { k: 'tours', l: 'Tour Scheduler' }] },
    { sec: 'OPERATIONS', items: [{ k: 'apartments', l: 'Apartment Inventory' }, { k: 'makeready', l: 'Make-Ready Board' }, { k: 'maintenance', l: 'Maintenance' }, { k: 'housekeeping', l: 'Housekeeping' }] },
    { sec: 'FINANCIAL', items: [{ k: 'ledger', l: 'Financial Ledger' }, { k: 'revenue', l: 'Revenue Leakage' }, { k: 'concessions', l: 'Concession Approvals' }, { k: 'loc', l: 'LOC Calculator' }, { k: 'competitors', l: 'Competitor Intel' }] },
    { sec: 'ACTIVITY', items: [{ k: 'notes', l: '📋 Activity Notes' }, { k: 'mileage', l: '🚗 Mileage & Expenses' }, { k: 'tasks', l: 'Tasks' }, { k: 'gift', l: '🎁 Gift & Gratuity' }, { k: 'aircall', l: '☎️ Aircall — Call · Text · Email' }] },
    { sec: 'ADMIN', items: [{ k: 'alertsettings', l: '🔔 Alert Settings' }, { k: 'finsettings', l: '💵 Financial Settings' }, { k: 'reports', l: 'Reports' }, { k: 'settings', l: 'Settings' }] },
  ],
  marketer: [
    { sec: 'SALES', items: [{ k: 'dashboard', l: 'Sales Dashboard' }, { k: 'leads', l: 'Lead Pipeline' }, { k: 'referrals', l: 'Referral Pipeline' }, { k: 'paidrefs', l: '💰 Paid Referral Portal' }, { k: 'tours', l: 'Tours' }, { k: 'refs', l: 'Referral Sources' }] },
    { sec: 'ACTIVITY', items: [{ k: 'notes', l: '📋 Activity Notes' }, { k: 'mileage', l: '🚗 Mileage & Expenses' }, { k: 'tasks', l: 'Tasks' }, { k: 'gift', l: '🎁 Gift & Gratuity' }, { k: 'aircall', l: '☎️ Aircall — Call · Text · Email' }] },
  ],
  salesadmissions: [
    { sec: 'EXECUTIVE', items: [{ k: 'dashboard', l: 'Sales/Admissions Dashboard' }, { k: 'occupancy', l: 'Occupancy Overview' }] },
    { sec: 'SALES', items: [{ k: 'leads', l: 'Lead Pipeline' }, { k: 'referrals', l: 'Referral Pipeline' }, { k: 'paidrefs', l: '💰 Paid Referral Portal' }, { k: 'tours', l: 'Tour Scheduler' }, { k: 'refs', l: 'Referral Sources' }] },
    { sec: 'OPERATIONS', items: [{ k: 'apartments', l: 'Apartment Inventory' }, { k: 'makeready', l: 'Make-Ready Board' }, { k: 'maintenance', l: 'Maintenance Tickets' }, { k: 'housekeeping', l: 'Housekeeping Tasks' }] },
    { sec: 'FINANCIAL', items: [{ k: 'ledger', l: 'Financial Ledger' }, { k: 'revenue', l: 'Revenue Leakage' }, { k: 'concessions', l: 'Concession Approvals' }, { k: 'loc', l: 'LOC Calculator' }] },
    { sec: 'ACTIVITY', items: [{ k: 'notes', l: '📋 Activity Notes' }, { k: 'mileage', l: '🚗 Mileage & Expenses' }, { k: 'tasks', l: 'Tasks' }, { k: 'gift', l: '🎁 Gift & Gratuity' }, { k: 'aircall', l: '☎️ Aircall — Call · Text · Email' }] },
  ],
  maintenance: [
    { sec: 'MY WORK', items: [{ k: 'dashboard', l: 'My Queue' }, { k: 'maintenance', l: 'Maintenance Tickets' }, { k: 'makeready', l: 'Make-Ready Tasks' }, { k: 'apartments', l: 'Unit Status' }, { k: 'tasks', l: 'Tasks' }] },
  ],
  housekeeping: [
    { sec: 'MY WORK', items: [{ k: 'dashboard', l: 'My Queue' }, { k: 'housekeeping', l: 'Housekeeping Tasks' }, { k: 'makeready', l: 'Make-Ready Clean' }, { k: 'maintenance', l: 'Maintenance View' }, { k: 'apartments', l: 'Unit Status' }, { k: 'tasks', l: 'Tasks' }] },
  ],
};

export const ROLE_LABELS: Record<MaxRole, string> = {
  director: 'Executive Director',
  salesadmissions: 'Sales/Admissions',
  owner: 'Owner / Investor',
  admin: 'Administrator',
  marketer: 'Sales Marketer',
  maintenance: 'Maintenance',
  housekeeping: 'Housekeeping',
};

// Role <select> option order (reference roleSelect <option> order).
export const ROLE_OPTIONS: MaxRole[] = ['director', 'salesadmissions', 'owner', 'admin', 'marketer', 'maintenance', 'housekeeping'];

export const ROLE_DEFAULT_TAB: Record<MaxRole, MaxTabKey> = {
  director: 'dashboard', salesadmissions: 'dashboard', owner: 'dashboard',
  admin: 'dashboard', marketer: 'dashboard', maintenance: 'maintenance', housekeeping: 'housekeeping',
};

// Topbar title after a role switch (reference changeRole titleMap).
export const ROLE_TITLE: Record<MaxRole, string> = {
  maintenance: 'Maintenance Tickets', housekeeping: 'Housekeeping Tasks',
  owner: 'Portfolio Dashboard', director: 'Executive Dashboard',
  salesadmissions: 'Sales/Admissions Dashboard', admin: 'Dashboard', marketer: 'Dashboard',
};

// Topbar title per tab (reference go() titles map).
export const TAB_TITLES: Record<MaxTabKey, string> = {
  dashboard: 'Dashboard', occupancy: 'Occupancy Overview', leads: 'Lead Pipeline',
  mileage: 'Mileage Tracker & Expenses', notes: 'Activity Notes', paidrefs: 'Paid Referral Portal',
  gift: 'Gift & Gratuity Tracking', alertsettings: 'Alert Settings', finsettings: 'Financial Settings',
  referrals: 'Referral Pipeline', tours: 'Tour Scheduler', refs: 'Referral Sources',
  apartments: 'Apartment Inventory', makeready: 'Make-Ready Board', maintenance: 'Maintenance Tickets',
  housekeeping: 'Housekeeping Tasks', ledger: 'Financial Ledger', revenue: 'Revenue Leakage',
  concessions: 'Concession Approvals', loc: 'LOC Pricing Calculator', competitors: 'Competitor Intel',
  tasks: 'Tasks', reports: 'Reports Center', settings: 'Settings', aircall: 'Aircall — Call · Text · Email',
};

// Mobile bottom-nav tabs (reference #mobile-nav).
export const MOBILE_BOTTOM_NAV: Array<{ key: MaxTabKey; icon: string; label: string }> = [
  { key: 'dashboard', icon: '🏠', label: 'Home' },
  { key: 'leads', icon: '👥', label: 'Leads' },
  { key: 'notes', icon: '📋', label: 'Notes' },
  { key: 'aircall', icon: '☎️', label: 'Aircall' },
];

export const INITIAL_PAGE_TITLE = 'Executive Dashboard';
export const SUBTITLE = 'Sunrise Senior Living — February 2026';
export const PRICING_HREF = '/communitylink/pricing';
export const STRIPE_URL = 'https://buy.stripe.com/5kQ14odssbU31qTdJHfEk0t';
