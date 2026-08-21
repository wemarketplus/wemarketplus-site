// Seed data + static config for the CommunityLink Max CRM demo — verbatim from
// the reference (communitylinkmax-demo.html). Static values only.
import type {
  ActivityNote,
  AlertDef,
  AlertSetting,
  Apartment,
  Competitor,
  Concession,
  FinDef,
  GiftLog,
  HkTask,
  Lead,
  LeadStatus,
  LeakItem,
  LocBase,
  MaintTicket,
  MileageLog,
  MrTicket,
  PaidRefPortal,
  PaidReferral,
  RefSource,
  RevenueMonth,
  Task,
  Tour,
} from '../types/maxTypes';

const DAY = 86400000;
const HOUR = 3600000;

export const SEED_LEADS: Lead[] = [
  { id: 1, name: 'Dorothy Harrison', care: 'Independent Living', status: 'Tour Scheduled', urgency: 'High', source: 'Physician', phone: '(214)555-0142', fu: '2026-02-14', notes: 'Son James is POA.' },
  { id: 2, name: 'Walter Simmons', care: 'Assisted Living', status: 'Inquiry', urgency: 'Medium', source: 'Website', phone: '(972)555-0278', fu: '2026-02-16', notes: 'Looking for 2BR.' },
  { id: 3, name: 'Gloria Tran', care: 'Memory Care', status: 'Proposal Sent', urgency: 'High', source: 'Hospital Discharge', phone: '(469)555-0391', fu: '2026-02-13', notes: 'MNSD diagnosis. Quick move wanted.' },
  { id: 4, name: 'Raymond Flores', care: 'Independent Living', status: 'Follow-up', urgency: 'Low', source: 'Community Event', phone: '(817)555-0456', fu: '2026-03-05', notes: 'Not ready yet.' },
  { id: 5, name: 'Edna Michaels', care: 'Assisted Living', status: 'Tour Scheduled', urgency: 'Medium', source: 'Google', phone: '(214)555-0567', fu: '2026-02-15', notes: 'Has VA benefits.' },
  { id: 6, name: 'James Owens', care: 'Memory Care', status: 'Move-In', urgency: '', source: 'Physician', phone: '(972)555-0678', fu: '', notes: 'Moved in Jan 28.' },
];

export const SEED_APTS: Apartment[] = [
  { id: 1, unit: '101', type: '1BR/1BA', care: 'IL', sqft: 620, status: 'occupied', resident: 'Vera Holmes', rate: 3400, mrTasks: 0 },
  { id: 2, unit: '102', type: '2BR/2BA', care: 'IL', sqft: 890, status: 'available', resident: '', rate: 3800, mrTasks: 0 },
  { id: 3, unit: '103', type: 'Studio', care: 'AL', sqft: 420, status: 'make_ready', resident: '', rate: 4200, mrTasks: 4 },
  { id: 4, unit: '104', type: '1BR/1BA', care: 'MC', sqft: 540, status: 'on_notice', resident: 'Earl Davis', rate: 5600, mrTasks: 0 },
  { id: 5, unit: '105', type: '2BR/2BA', care: 'IL', sqft: 910, status: 'occupied', resident: 'Ruth & Harold Kim', rate: 3900, mrTasks: 0 },
  { id: 6, unit: '106', type: 'Studio', care: 'AL', sqft: 400, status: 'reserved', resident: 'Martha Jones (incoming)', rate: 4100, mrTasks: 0 },
  { id: 7, unit: '107', type: '1BR/1BA', care: 'IL', sqft: 650, status: 'occupied', resident: 'Frank Torres', rate: 3500, mrTasks: 0 },
  { id: 8, unit: '108', type: '2BR/2BA', care: 'MC', sqft: 870, status: 'make_ready', resident: '', rate: 5800, mrTasks: 3 },
];

export const SEED_MR_TICKETS: MrTicket[] = [
  { id: 1, unit: '103', type: 'Studio', moveout: '2026-01-30', target: '2026-02-15', pct: 60, tasks: ['Trash out', 'Locks changed', 'Paint in progress', 'Carpet scheduled', 'HVAC check', 'Final clean'], assignee: 'Carlos R.' },
  { id: 2, unit: '108', type: '2BR/2BA', moveout: '2026-01-25', target: '2026-02-14', pct: 75, tasks: ['Trash out', 'Locks changed', 'Paint done', 'Window repair done', 'Deep clean in progress', 'Inspection'], assignee: 'Marcus T.' },
];

export const SEED_MAINT_TICKETS: MaintTicket[] = [
  { id: 1, ticket: 'M-001', unit: '101', resident: 'Vera Holmes', issue: 'Bathroom faucet dripping', priority: 'Low', status: 'open', assignee: 'Carlos R.', created: '2026-02-10' },
  { id: 2, ticket: 'M-002', unit: '105', resident: 'Ruth Kim', issue: 'Thermostat not responding', priority: 'High', status: 'in_progress', assignee: 'Marcus T.', created: '2026-02-11' },
  { id: 3, ticket: 'M-003', unit: '103', resident: '', issue: 'Paint touch-up make-ready', priority: 'Med', status: 'scheduled', assignee: 'Carlos R.', created: '2026-02-01' },
  { id: 4, ticket: 'M-004', unit: '108', resident: '', issue: 'Window repair make-ready', priority: 'High', status: 'in_progress', assignee: 'Marcus T.', created: '2026-02-05' },
  { id: 5, ticket: 'M-005', unit: '107', resident: 'Frank Torres', issue: 'Light fixture replacement', priority: 'Low', status: 'completed', assignee: 'Carlos R.', created: '2026-02-08' },
];

export const SEED_HK_TASKS: HkTask[] = [
  { id: 1, task: 'Unit 103 Make-Ready Deep Clean', unit: '103', type: 'Make-Ready', status: 'in_progress', assignee: 'Maria G.', due: '2026-02-13' },
  { id: 2, task: 'Unit 108 Make-Ready Deep Clean', unit: '108', type: 'Make-Ready', status: 'not_started', assignee: 'Lisa P.', due: '2026-02-14' },
  { id: 3, task: 'Common Areas Daily Clean', unit: 'Common', type: 'Daily', status: 'completed', assignee: 'Maria G.', due: '2026-02-12' },
  { id: 4, task: 'Dining Room Weekly Deep Clean', unit: 'Dining', type: 'Deep Clean', status: 'scheduled', assignee: 'Team', due: '2026-02-15' },
  { id: 5, task: 'Unit 102 Vacancy Clean', unit: '102', type: 'Vacancy', status: 'completed', assignee: 'Lisa P.', due: '2026-02-09' },
];

export const SEED_REFERRALS: RefSource[] = [
  { id: 1, name: 'Dr. Amanda Chen', type: 'Physician', org: 'Dallas Medical Group', leads: 8, last: '2026-02-10' },
  { id: 2, name: 'Sarah Kim RN', type: 'Hospital', org: 'Parkland Hospital', leads: 5, last: '2026-02-08' },
  { id: 3, name: 'Tom Walsh SW', type: 'Social Worker', org: 'Methodist Senior Care', leads: 3, last: '2026-01-30' },
];

export const SEED_TASKS: Task[] = [
  { id: 1, title: 'Schedule Unit 104 make-ready for Mar 1', due: '2026-02-20', priority: 'High', done: false },
  { id: 2, title: 'Call Dorothy Harrison — tour confirmation', due: '2026-02-13', priority: 'High', done: false },
  { id: 3, title: 'Review Unit 103 make-ready progress', due: '2026-02-13', priority: 'Med', done: false },
  { id: 4, title: 'Submit mileage report', due: '2026-02-14', priority: 'Low', done: true },
];

export const SEED_NOTES: ActivityNote[] = [
  { id: 201, type: 'aircall', comm_type: 'call', contact_name: 'Dorothy Harrison', summary: 'Tour confirmed for Friday 10am. Son James attending as POA.', outcome: 'Connected — tour scheduled', next_step: 'Prepare tour materials', follow_up_date: '2026-02-14', created_at: new Date(Date.now() - HOUR).toISOString(), user_name: 'Sarah M.' },
  { id: 202, type: 'aircall', comm_type: 'text', contact_name: 'Gloria Tran', summary: 'Text sent: Hi Gloria, just confirming your proposal review tomorrow at 2pm.', outcome: 'Delivered', next_step: 'Follow up after review', follow_up_date: '2026-02-14', created_at: new Date(Date.now() - DAY).toISOString(), user_name: 'Sarah M.' },
  { id: 203, type: 'manual', comm_type: 'manual', contact_name: 'Walter Simmons', summary: 'Family called in — son James inquiring about 2BR AL availability. Warm lead.', outcome: 'Inquiry logged', next_step: 'Schedule tour', follow_up_date: '2026-02-16', created_at: new Date(Date.now() - 2 * DAY).toISOString(), user_name: 'Sarah M.' },
  { id: 204, type: 'aircall', comm_type: 'email', contact_name: 'Dr. Amanda Chen', summary: 'Email sent — Subject: Thank You for Your Referral!', outcome: 'Sent', next_step: 'Follow up in 3 days', follow_up_date: '2026-02-17', created_at: new Date(Date.now() - 3 * DAY).toISOString(), user_name: 'Admin' },
  { id: 205, type: 'aircall', comm_type: 'missed_call', contact_name: 'Edna Michaels', summary: 'Call attempt failed — no answer. Left voicemail.', outcome: 'Voicemail left', next_step: 'Try again tomorrow AM', follow_up_date: '2026-02-15', created_at: new Date(Date.now() - 4 * DAY).toISOString(), user_name: 'Sarah M.' },
];

export const SEED_PAID_REFERRALS: PaidReferral[] = [
  { id: 101, source: 'A Place for Mom', partner: 'APFM', type: 'Paid', fee: 2000, feeStatus: 'Pending', name: 'Dorothy Harrison', care: 'Independent Living', stage: 'Tour Scheduled', urgency: 'High', assigned: 'Sarah M.', phone: '(214)555-0142', tourDate: '2026-02-14', moveInTarget: '2026-03-01', notes: 'Son James is POA. APFM referral fee $2,000 pending move-in.', lostReason: '', created: '2026-02-01' },
  { id: 102, source: 'Caring.com', partner: 'Caring', type: 'Paid', fee: 1500, feeStatus: 'Pending', name: 'Gloria Tran', care: 'Memory Care', stage: 'Deposit Pending', urgency: 'High', assigned: 'Sarah M.', phone: '(469)555-0391', tourDate: '2026-02-10', moveInTarget: '2026-02-20', notes: 'MNSD diagnosis. Proposal sent. Caring.com fee $1,500 on move-in.', lostReason: '', created: '2026-01-28' },
  { id: 103, source: 'Dr. Amanda Chen', partner: 'Internal', type: 'Organic', fee: 0, feeStatus: 'N/A', name: 'Walter Simmons', care: 'Assisted Living', stage: 'New Referral', urgency: 'Medium', assigned: 'Sarah M.', phone: '(972)555-0278', tourDate: '', moveInTarget: '', notes: 'Looking for 2BR AL. Dr. Chen referred directly.', lostReason: '', created: '2026-02-05' },
  { id: 104, source: 'SeniorAdvisor', partner: 'SA', type: 'Paid', fee: 1800, feeStatus: 'Pending', name: 'Edna Michaels', care: 'Assisted Living', stage: 'Tour Scheduled', urgency: 'Medium', assigned: 'Sarah M.', phone: '(214)555-0567', tourDate: '2026-02-15', moveInTarget: '2026-03-15', notes: 'VA benefits confirmed. SeniorAdvisor fee $1,800 on move-in.', lostReason: '', created: '2026-02-03' },
  { id: 105, source: 'Parkland Hospital', partner: 'Internal', type: 'Organic', fee: 0, feeStatus: 'N/A', name: 'Raymond Flores', care: 'Independent Living', stage: 'Family Reached', urgency: 'Low', assigned: 'Sarah M.', phone: '(817)555-0456', tourDate: '', moveInTarget: '2026-04-01', notes: '60-day timeline. Family researching options.', lostReason: '', created: '2026-01-15' },
  { id: 106, source: 'A Place for Mom', partner: 'APFM', type: 'Paid', fee: 2000, feeStatus: 'Paid', name: 'James Owens', care: 'Memory Care', stage: 'Moved In', urgency: '', assigned: 'Sarah M.', phone: '(972)555-0678', tourDate: '2026-01-10', moveInTarget: '2026-01-28', notes: 'Moved in Jan 28. APFM fee $2,000 PAID.', lostReason: '', created: '2026-01-03' },
];

export const REFERRAL_STAGES = ['New Referral', 'Contact Attempted', 'Family Reached', 'Assessment Scheduled', 'Tour Scheduled', 'Touring', 'Deposit Pending', 'Approved', 'Move-In Scheduled', 'Moved In', 'Lost'];
export const STAGE_COLORS: Record<string, string> = {
  'New Referral': '#3d9ee8', 'Contact Attempted': '#a78bfa', 'Family Reached': '#f59e0b',
  'Assessment Scheduled': '#f59e0b', 'Tour Scheduled': '#4fc87a', Touring: '#4fc87a',
  'Deposit Pending': '#f87171', Approved: '#4fc87a', 'Move-In Scheduled': '#4fc87a',
  'Moved In': '#4fc87a', Lost: '#f87171',
};
export const STAGE_BADGE: Record<string, string> = {
  'New Referral': 'bb', 'Contact Attempted': 'bx', 'Family Reached': 'ba',
  'Assessment Scheduled': 'ba', 'Tour Scheduled': 'bg', Touring: 'bg',
  'Deposit Pending': 'br', Approved: 'bg', 'Move-In Scheduled': 'bg',
  'Moved In': 'bg', Lost: 'br',
};

export const SEED_PAID_REFS_PORTAL: PaidRefPortal[] = [
  { id: 'pr1', prospect_name: 'Dorothy Harrison', source_name: 'A Place for Mom', prospect_phone: '(214)555-0142', care_level: 'Independent Living', budget_range: '$3,200–$4,000/mo', move_in_timeframe: '30 days', urgency: 'hot', referral_fee: 2000, fee_status: 'pending', stage: 'Tour Scheduled', source_contact: 'Rachel (APFM Advisor)', source_notes: 'Family toured 3 other communities. Very motivated. Son James is POA.', received_at: new Date(Date.now() - HOUR).toISOString(), assigned_name: 'Sarah M.' },
  { id: 'pr2', prospect_name: 'Gloria Tran', source_name: 'Caring.com', prospect_phone: '(469)555-0391', care_level: 'Memory Care', budget_range: '$5,000–$6,500/mo', move_in_timeframe: 'ASAP', urgency: 'hot', referral_fee: 1500, fee_status: 'pending', stage: 'Assessment Scheduled', source_contact: 'Caring.com Lead', source_notes: 'MCI diagnosis confirmed. Family ready to move quickly.', received_at: new Date(Date.now() - DAY).toISOString(), assigned_name: 'Sarah M.' },
  { id: 'pr3', prospect_name: 'Walter Simmons', source_name: 'SeniorAdvisor', prospect_phone: '(972)555-0278', care_level: 'Assisted Living', budget_range: '$4,000–$5,000/mo', move_in_timeframe: '60 days', urgency: 'warm', referral_fee: 1800, fee_status: 'pending', stage: 'New Referral', source_contact: 'SA Platform', source_notes: 'VA benefits confirmed.', received_at: new Date(Date.now() - 2 * DAY).toISOString(), assigned_name: 'Unassigned' },
  { id: 'pr4', prospect_name: 'James Owens', source_name: 'A Place for Mom', prospect_phone: '(972)555-0678', care_level: 'Memory Care', budget_range: '$5,500+/mo', move_in_timeframe: 'Moved In', urgency: '', referral_fee: 2000, fee_status: 'paid', stage: 'Moved In', source_contact: 'Rachel (APFM)', source_notes: 'Successfully moved in Jan 28.', received_at: new Date(Date.now() - 30 * DAY).toISOString(), assigned_name: 'Sarah M.' },
];
export const PR_STAGES = ['New Referral', 'Contact Attempted', 'Family Reached', 'Assessment Scheduled', 'Tour Scheduled', 'Touring', 'Deposit Pending', 'Approved', 'Move-In Scheduled', 'Moved In', 'Lost'];
export const PR_PIPELINE_STAGES = ['New Referral', 'Tour Scheduled', 'Assessment Scheduled', 'Deposit Pending', 'Moved In', 'Lost'];
export const PR_STAGE_COLORS: Record<string, string> = { 'New Referral': '#3d9ee8', 'Tour Scheduled': '#4fc87a', 'Assessment Scheduled': '#f59e0b', 'Moved In': '#4fc87a', Lost: '#f87171', 'Deposit Pending': '#f87171' };
export const PR_STAGE_BADGE: Record<string, string> = { 'New Referral': 'bb', 'Tour Scheduled': 'bg', 'Assessment Scheduled': 'ba', 'Moved In': 'bg', Lost: 'br', 'Deposit Pending': 'br' };

export const SEED_REVENUE_MONTHS: RevenueMonth[] = [
  { mo: 'Sep', bud: 180000, act: 172400 }, { mo: 'Oct', bud: 182000, act: 178900 },
  { mo: 'Nov', bud: 180000, act: 175200 }, { mo: 'Dec', bud: 185000, act: 168900 },
  { mo: 'Jan', bud: 183000, act: 181200 }, { mo: 'Feb', bud: 186000, act: 161000 },
];

export const SEED_CONCESSIONS: Concession[] = [
  { id: 'C-001', unit: '102', resident: 'Walter Simmons', type: 'First Month Free', value: 4200, status: 'pending', by: 'Sarah M.' },
  { id: 'C-002', unit: '106', resident: 'Martha Jones', type: 'Move-In Fee Waiver', value: 1500, status: 'approved', by: 'James K.' },
  { id: 'C-003', unit: '103', resident: 'Incoming Lead', type: '2 Months Free Parking', value: 600, status: 'denied', by: 'Maria L.' },
];

export const SEED_COMPETITORS: Competitor[] = [
  { name: 'Sunrise Gardens AL', city: 'Dallas', dist: 2.1, il: 'N/A', al: '$4,200', mc: '$5,800', occ: '88%', notes: 'New renovations Q1' },
  { name: 'Heritage Pines Senior', city: 'Plano', dist: 4.5, il: '$3,400', al: '$4,600', mc: 'N/A', occ: '94%', notes: 'Waitlist for 2BR' },
  { name: 'Cottonwood Creek', city: 'Irving', dist: 6.2, il: '$3,100', al: '$3,900', mc: '$5,200', occ: '82%', notes: 'Offering 1st month free' },
  { name: 'Meadowbrook Place', city: 'Garland', dist: 8.0, il: '$3,600', al: '$4,800', mc: '$6,200', occ: '91%', notes: 'Luxury renovation done' },
];

export const SEED_LEAK_ITEMS: LeakItem[] = [
  { issue: '2 Units Vacant — Make-Ready Delay', type: 'Vacancy Loss', amount: 8400, status: 'ongoing' },
  { issue: 'Unit 102 Rate Below Market (IL)', type: 'Rate Gap', amount: 1800, status: 'review' },
  { issue: 'Concession Not Recovered — Unit 106', type: 'Concession', amount: 2400, status: 'active' },
  { issue: 'Parking Not Billed — 3 Residents', type: 'Revenue Miss', amount: 900, status: 'fix_needed' },
  { issue: 'Unpaid Move-Out Fee — Unit 204', type: 'Collection', amount: 1800, status: 'pending' },
];

export const SEED_LOC_BASE: LocBase = { IL: 3200, AL: 4500, MC: 5800, addon: 150 };
export const LOC_SERVICES = ['Medication mgmt, minor ADL', '+ Bathing, dressing, mobility', '+ Incontinence, transfers', '+ 24hr supervision, secured unit', '+ Dementia care, behavioral support'];

export const DEMO_MILEAGE_RATE = 0.67;
export const SEED_MILEAGE_LOGS: MileageLog[] = [
  { id: 'ml1', date: new Date().toISOString().split('T')[0], from_addr: 'Office, Dallas TX', to_addr: 'Baylor Medical Center, Dallas TX', miles: 14.2, purpose: 'Referral visit — Dr. Patel', reimbursement: 9.51, status: 'approved', receipt: null, expense_type: '', expense_amt: 0, submitted_by: 'Sarah M.' },
  { id: 'ml2', date: new Date(Date.now() - DAY).toISOString().split('T')[0], from_addr: 'Office, Dallas TX', to_addr: 'North Park Rehab, Dallas TX', miles: 8.7, purpose: 'Tour coordination', reimbursement: 5.83, status: 'approved', receipt: null, expense_type: 'parking', expense_amt: 6.0, submitted_by: 'Sarah M.' },
  { id: 'ml3', date: new Date(Date.now() - 2 * DAY).toISOString().split('T')[0], from_addr: 'Office, Dallas TX', to_addr: 'Prestonwood SNF, Plano TX', miles: 22.4, purpose: 'In-service lunch', reimbursement: 15.01, status: 'pending', receipt: null, expense_type: 'meals', expense_amt: 24.5, submitted_by: 'Sarah M.' },
];
export const MILEAGE_EXPENSE_TYPES = ['parking', 'tolls', 'meals', 'supplies', 'event', 'marketing', 'other'];

export const DEMO_GIFT_LIMIT = 15.0;
export const SEED_GIFT_LOGS: GiftLog[] = [
  { id: 'g1', recipient_name: 'Sarah M.', facility_name: 'North Park Rehab', gift_type: 'Meal', gift_value: 12.5, visit_date: '2026-02-10', compliance_ok: true, logged_by_name: 'Ericka T.' },
  { id: 'g2', recipient_name: 'Dr. Patel', facility_name: 'Baylor Hospital', gift_type: 'Branded Item', gift_value: 15.0, visit_date: '2026-02-08', compliance_ok: true, logged_by_name: 'Ericka T.' },
  { id: 'g3', recipient_name: 'Office Staff', facility_name: 'Prestonwood SNF', gift_type: 'Coffee', gift_value: 22.0, visit_date: '2026-02-05', compliance_ok: false, logged_by_name: 'Mike R.' },
];
export const GIFT_TYPES = ['Meal', 'Gift Card', 'Branded Item', 'Flowers', 'Coffee', 'Other'];

export const SEED_ALERTS: Record<string, AlertSetting> = {
  paid_referral: { enabled: true, channel: 'email', roles: ['admin', 'director', 'salesadmissions'] },
  organic_lead: { enabled: true, channel: 'email', roles: ['admin', 'director', 'salesadmissions'] },
  tour: { enabled: true, channel: 'email', roles: ['admin', 'director', 'salesadmissions'] },
  move_in: { enabled: true, channel: 'email', roles: ['admin', 'director', 'salesadmissions'] },
  lost_lead: { enabled: false, channel: 'email', roles: ['admin', 'director'] },
  failed_payment: { enabled: true, channel: 'email', roles: ['admin'] },
};
export const ALERT_DEFS: AlertDef[] = [
  { key: 'paid_referral', label: 'New Paid Referral', desc: 'A Place for Mom, Caring.com, SeniorAdvisor, etc.' },
  { key: 'organic_lead', label: 'New Organic Lead', desc: 'Website, walk-in, direct inquiry' },
  { key: 'tour', label: 'Tour Scheduled', desc: 'When a tour is booked' },
  { key: 'move_in', label: 'Move-In Confirmed', desc: 'When a resident moves in' },
  { key: 'lost_lead', label: 'Lead Marked Lost', desc: 'When a lead is marked lost' },
  { key: 'failed_payment', label: 'Failed Payment', desc: 'Billing or subscription failure' },
];
export const ALERT_ROLES = ['admin', 'director', 'salesadmissions', 'marketer'];
export const ALERT_CHANNELS = ['email', 'sms', 'inapp', 'all'];

export const SEED_FIN_SETTINGS: Record<string, string> = { mileage_rate: '0.67', gift_gratuity_limit: '15.00', parking_max: '20.00', meal_max: '25.00', referral_fee_default: '2000' };
export const FIN_DEFS: FinDef[] = [
  { key: 'mileage_rate', label: 'Mileage Reimbursement Rate', hint: 'Per mile (IRS 2024: $0.67)', suffix: '/mile' },
  { key: 'gift_gratuity_limit', label: 'Gift & Gratuity Limit', hint: 'Per visit — CMS compliance', suffix: '/visit' },
  { key: 'parking_max', label: 'Parking Expense Max', hint: 'Per day max', suffix: '/day' },
  { key: 'meal_max', label: 'Meal Expense Max', hint: 'Per person if allowed', suffix: '' },
  { key: 'referral_fee_default', label: 'Default Referral Fee', hint: 'Auto-fill when adding paid referral', suffix: '' },
];

export const AC_EMAIL_TPL: Record<string, { s: string; b: string }> = {
  tour: { s: 'Your Tour at Sunrise Senior Living is Confirmed!', b: 'Dear [Name],\n\nYour tour is confirmed!\n\n📅 Date: [Date]\n🕙 Time: 10:00 AM\n📍 Address: 1234 Sunrise Dr, Dallas TX\n\nWe\'re excited to meet you!\n\n[Your Name] | Sunrise Senior Living' },
  proposal: { s: 'Your Personalized Care & Pricing Overview', b: 'Dear [Name],\n\nThank you for your interest. Here is your personalized pricing:\n\nIL: from $3,200/mo\nAL: from $4,500/mo\nMC: from $5,800/mo\n\n[Your Name] | [Phone]' },
  thank: { s: 'Thank You for Your Referral!', b: 'Dear [Name],\n\nThank you for trusting us with your referral. We\'ll make sure they have an exceptional experience.\n\nGratefully,\n[Your Name]' },
  followup: { s: 'Following Up — Sunrise Senior Living', b: 'Dear [Name],\n\nI wanted to follow up and check in. We\'d love to help your family find the right home.\n\nDo you have 10 minutes this week?\n\n[Your Name] | [Phone]' },
  movein: { s: 'Welcome to Sunrise Senior Living — Move-In Details', b: 'Dear [Name],\n\nWe\'re so excited to welcome [Resident] to Sunrise Senior Living!\n\n📅 Move-In Date: [Date]\n🏠 Unit: [Unit]\n\nSee you soon!\n[Your Name]' },
};

// Aircall quick-insert text templates (rAircall text panel).
export const AC_TEXT_TPL: Array<{ v: string; l: string }> = [
  { v: 'Hi {name}! This is Sarah from Sunrise Senior Living. We have a lovely unit available — would you like to tour this week?', l: 'Tour Invite' },
  { v: 'Hi {name}, just following up on your inquiry. Are you available for a quick call?', l: 'Follow-Up' },
  { v: "Hi {name}, confirming your tour tomorrow at 10am. We're excited to see you!", l: 'Tour Reminder' },
];

export const TOURS: Tour[] = [
  { name: 'Dorothy Harrison', care: 'IL', date: '2026-02-14', time: '10:00 AM', guide: 'Sarah M.', status: 'Confirmed' },
  { name: 'Edna Michaels', care: 'AL', date: '2026-02-15', time: '2:00 PM', guide: 'Sarah M.', status: 'Confirmed' },
  { name: 'New Inquiry', care: 'IL', date: '2026-02-17', time: '11:00 AM', guide: 'TBD', status: 'Pending' },
];

export const SEED_NEXT_ID = 200;
export const LEAD_FILTER_STATUSES: LeadStatus[] = ['Inquiry', 'Tour Scheduled', 'Proposal Sent', 'Move-In'];
export const LEAD_STATUS_CYCLE: LeadStatus[] = ['Inquiry', 'Follow-up', 'Tour Scheduled', 'Proposal Sent', 'Decision Pending', 'Move-In'];

// Dashboard "Operations Status" rows — [label, apt-status key, color]. Shared by
// the Owner and Sales/Admissions dashboards (reference rOwnerDash / rSADash).
export const OPS_STATUS_ROWS: Array<[string, string, string]> = [
  ['Occupied', 'occupied', '#4fc87a'],
  ['Available', 'available', '#3d9ee8'],
  ['Make-Ready', 'make_ready', '#f59e0b'],
  ['On-Notice', 'on_notice', '#f87171'],
];

// Competitor AL rate comparison rows — [community, rate, color] (rCompetitors).
export const RATE_COMPARE: Array<[string, string, string]> = [
  ['Sunrise Senior Living (You)', '$4,100', '#4fc87a'],
  ['Meadowbrook Place', '$4,800', '#3d9ee8'],
  ['Heritage Pines', '$4,600', '#a78bfa'],
  ['Sunrise Gardens AL', '$4,200', '#f59e0b'],
  ['Cottonwood Creek', '$3,900', '#f87171'],
];

// Max bar height baseline for the ledger revenue-vs-budget chart (rLedger).
export const LEDGER_CHART_MAX = 190000;
