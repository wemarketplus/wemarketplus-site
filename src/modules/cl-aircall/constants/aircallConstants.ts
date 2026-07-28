// Aircall quick-insert templates, ported from the Max demo (maxData.ts
// AC_TEXT_TPL / AC_EMAIL_TPL). `{name}` / `[Name]` placeholders are filled with
// the selected lead's name at compose time.

export interface TextTemplate {
  label: string;
  body: string;
}

export const AIRCALL_TEXT_TEMPLATES: readonly TextTemplate[] = [
  {
    label: 'Tour Invite',
    body: 'Hi {name}! This is your team at the community. We have a lovely unit available — would you like to tour this week?',
  },
  {
    label: 'Follow-Up',
    body: 'Hi {name}, just following up on your inquiry. Are you available for a quick call?',
  },
  {
    label: 'Tour Reminder',
    body: "Hi {name}, confirming your tour tomorrow at 10am. We're excited to see you!",
  },
];

export interface EmailTemplate {
  key: string;
  label: string;
  subject: string;
  body: string;
}

export const AIRCALL_EMAIL_TEMPLATES: readonly EmailTemplate[] = [
  {
    key: 'tour',
    label: 'Tour confirmation',
    subject: 'Your Tour is Confirmed!',
    body: 'Dear {name},\n\nYour tour is confirmed! We\'re excited to meet you.\n\nWarm regards,\nYour community team',
  },
  {
    key: 'proposal',
    label: 'Pricing overview',
    subject: 'Your Personalized Care & Pricing Overview',
    body: 'Dear {name},\n\nThank you for your interest. Here is your personalized pricing:\n\nIL: from $3,200/mo\nAL: from $4,500/mo\nMC: from $5,800/mo\n\nYour community team',
  },
  {
    key: 'thank',
    label: 'Thank you (referral)',
    subject: 'Thank You for Your Referral!',
    body: 'Dear {name},\n\nThank you for trusting us with your referral. We\'ll make sure they have an exceptional experience.\n\nGratefully,\nYour community team',
  },
  {
    key: 'followup',
    label: 'Follow-up',
    subject: 'Following Up',
    body: 'Dear {name},\n\nI wanted to follow up and check in. We\'d love to help your family find the right home.\n\nDo you have 10 minutes this week?\n\nYour community team',
  },
  {
    key: 'movein',
    label: 'Move-in details',
    subject: 'Welcome — Move-In Details',
    body: 'Dear {name},\n\nWe\'re so excited to welcome you!\n\nSee you soon,\nYour community team',
  },
];

export type AircallChannel = 'text' | 'email';
