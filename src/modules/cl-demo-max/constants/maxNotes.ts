// Static config for the Activity Notes timeline + Aircall — option lists, comm
// metadata, and role display names. Mirrors the reference's COMM_META / option
// arrays / ROLE_USER_NAMES. Static values only.
import type { BadgeTone } from '@/shared/cl-demo';
import type { CommMeta } from '../types/maxTypes';

export const COMM_META: Record<string, CommMeta> = {
  call: { icon: '📞', label: 'Phone Call', color: '#3d9ee8', bg: 'rgba(61,158,232,.12)', border: 'rgba(61,158,232,.28)' },
  text: { icon: '💬', label: 'Text Message', color: '#a78bfa', bg: 'rgba(167,139,250,.12)', border: 'rgba(167,139,250,.28)' },
  email: { icon: '✉️', label: 'Email', color: '#f59e0b', bg: 'rgba(245,158,11,.12)', border: 'rgba(245,158,11,.28)' },
  missed_call: { icon: '📵', label: 'Missed Call', color: '#f87171', bg: 'rgba(248,113,113,.12)', border: 'rgba(248,113,113,.28)' },
  visit: { icon: '🤝', label: 'Visit', color: '#4fc87a', bg: 'rgba(79,200,122,.08)', border: 'rgba(79,200,122,.22)' },
  manual: { icon: '📝', label: 'Manual Note', color: '#4fc87a', bg: 'rgba(79,200,122,.08)', border: 'rgba(79,200,122,.22)' },
};

export const ROLE_USER_NAMES: Record<string, string> = {
  director: 'Executive Director', salesadmissions: 'Sales/Admissions', owner: 'Owner / Investor',
  admin: 'Administrator', marketer: 'Sarah M. (Sales Marketer)', maintenance: 'Maintenance Team', housekeeping: 'Housekeeping Team',
};

export const ENTERED_BY_USERS = ['Sarah M. (Sales Marketer)', 'Mike R. (Marketer)', 'Angela T. (Director)', 'Admin', 'Executive Director', 'Sales/Admissions Team', 'Maintenance Team', 'Housekeeping Team', 'Aircall (System)'];

export const NOTE_TYPES: Array<{ value: string; label: string }> = [
  { value: 'manual', label: '📝 Manual Note' },
  { value: 'call', label: '📞 Phone Call' },
  { value: 'text', label: '💬 Text Message' },
  { value: 'email', label: '✉️ Email' },
  { value: 'visit', label: '🤝 Visit / In-Person' },
  { value: 'missed_call', label: '📵 Missed Call / Voicemail' },
];

export const NOTE_OUTCOMES = ['Tour scheduled', 'Proposal sent', 'Deposit received', 'Move-in confirmed', 'Follow-up needed', 'Left voicemail', 'No answer — will retry', 'Family requested more info', 'Not interested at this time', 'Competitor mentioned', 'Medical decline', 'Budget objection', 'Connected — great conversation', 'Family overwhelmed — needs time', 'Re-engagement scheduled'];

export const NOTE_NEXT_STEPS = ['Call family / POA', 'Schedule a tour', 'Send pricing / proposal', 'Send community overview / brochure', 'Confirm tour date', 'Follow up after tour', 'Request deposit', 'Confirm move-in date', 'Check unit readiness', 'Coordinate with maintenance / housekeeping', 'Send move-in paperwork', 'Contact referral source', 'Re-engage in 30 days', 'Mark as lost', 'Other — type below'];

export const NOTE_STAGES = ['Inquiry', 'Tour Scheduled', 'Touring', 'Proposal Sent', 'Deposit Pending', 'Approved', 'Move-In Scheduled', 'Moved In', 'Lost'];

export const REF_SOURCE_CONTACTS = [
  { id: 'rs-1', name: 'Sarah M.', type: 'Referral Source', sub: 'North Park Rehab · Case Manager' },
  { id: 'rs-2', name: 'Dr. Amanda Chen', type: 'Referral Source', sub: 'Dallas Medical Group · Physician' },
  { id: 'rs-3', name: 'Sarah Kim RN', type: 'Referral Source', sub: 'Parkland Hospital · Nurse' },
  { id: 'rs-4', name: 'Tom Walsh SW', type: 'Referral Source', sub: 'Methodist · Social Worker' },
];

export const CONTACT_TYPE_TONE: Record<string, BadgeTone> = {
  Lead: 'red', 'Paid Referral': 'amber', 'Referral Source': 'blue',
};
