// Legal copy ported verbatim from wemarketplus-site (privacy.html, tos.html,
// "sign baa"). Stored as structured data so LegalShell can render it and so
// the text lives in one reviewable place.
import type { LegalBlock } from '../types/legalTypes';

export const PRIVACY_EFFECTIVE = 'Effective January 1, 2024 — Last updated May 1, 2025';

export const PRIVACY_BLOCKS: readonly LegalBlock[] = [
  {
    paragraphs: [
      'We Market Plus LLC ("We Market Plus", "we", "us", or "our") operates the HospiceLink CRM platform. This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you use HospiceLink.',
    ],
  },
  {
    callout: {
      title: 'HIPAA Compliance Notice',
      body: 'HospiceLink is designed for use by HIPAA covered entities and their business associates. We Market Plus LLC functions as a Business Associate under HIPAA. A Business Associate Agreement (BAA) is executed with every subscribing organization before Protected Health Information (PHI) may be entered into the platform. PHI stored in HospiceLink is handled in accordance with the HIPAA Privacy Rule (45 CFR Part 164, Subpart E) and Security Rule (45 CFR Part 164, Subpart C).',
    },
  },
  {
    heading: '1. Information We Collect',
    paragraphs: [
      'Account Information: Name, email address, agency name, phone number, city/state, and payment information collected during registration and subscription management.',
      'CRM Data: Prospect records, clinical notes, task data, referral source information, mileage logs, and other data you enter into the platform. This data may include PHI and is governed by your BAA.',
      'Usage Data: Log data including IP addresses, browser type, pages visited, and feature usage. This information is used for security, troubleshooting, and service improvement.',
      'Payment Data: Payment processing is handled by Stripe, Inc. We do not store full credit card numbers. Stripe’s privacy policy is available at stripe.com/privacy.',
    ],
  },
  {
    heading: '2. How We Use Your Information',
    list: [
      'To provide, maintain, and improve the HospiceLink CRM platform',
      'To process subscriptions and manage billing',
      'To send transactional emails (account activation, password reset, billing notifications)',
      'To detect and prevent security incidents',
      'To comply with legal obligations including HIPAA, CCPA, and other applicable law',
      'To generate anonymized, aggregate analytics about platform usage (never PHI)',
    ],
  },
  {
    heading: '3. Data Sharing',
    paragraphs: [
      'We do not sell, rent, or trade your personal information or PHI to third parties for marketing purposes.',
      'We share data only with service providers who process it on our behalf under appropriate data processing agreements: Stripe (payments), Twilio SendGrid (email delivery), Anthropic PBC (AI features, no PHI transmitted), Render Inc. (infrastructure).',
      'We may disclose information when required by law, legal process, or to protect the rights and safety of HospiceLink users.',
    ],
  },
  {
    heading: '4. Data Retention and Deletion',
    paragraphs: [
      'Active account data is retained for the duration of your subscription plus 90 days after cancellation.',
      'When you request account deletion via your CRM settings, we immediately cancel your Stripe subscription, deactivate your account, and schedule all PHI and personal data for permanent deletion within 90 days. You will receive a confirmation email with the exact deletion date.',
      'Audit logs required for HIPAA compliance may be retained for up to 6 years as required by 45 CFR 164.530(j).',
    ],
  },
  {
    heading: '5. Your Rights (CCPA)',
    paragraphs: [
      'California residents have the right to: know what personal information is collected; request deletion of personal information; opt-out of the sale of personal information (we do not sell personal information); and non-discrimination for exercising these rights.',
      'To exercise these rights, contact us at privacy@wemarketplus.com.',
    ],
  },
  {
    heading: '6. Security',
    paragraphs: [
      'We implement appropriate technical and organizational measures to protect personal data including: AES-256 encryption at rest; TLS 1.2+ encryption in transit; bcrypt password hashing; role-based access controls; tamper-evident audit logging of administrative actions and record changes; and regular security review.',
    ],
  },
  {
    heading: '7. Cookies',
    paragraphs: [
      'HospiceLink uses only essential session cookies required for authentication. We do not use advertising or analytics cookies. The session cookie (hl_refresh) is HTTP-only, Secure, and SameSite=Strict.',
    ],
  },
  {
    heading: '8. Contact',
    paragraphs: [
      'For privacy questions, BAA requests, or data deletion requests: We Market Plus LLC — Email: privacy@wemarketplus.com — Support: support@wemarketplus.com',
    ],
  },
];

export const TOS_EFFECTIVE = 'Effective January 1, 2024 — Last updated May 1, 2025';

export const TOS_BLOCKS: readonly LegalBlock[] = [
  {
    paragraphs: [
      'These Terms of Service ("Terms") govern your use of HospiceLink CRM, operated by We Market Plus LLC ("We Market Plus", "us", or "our"). By subscribing to or using HospiceLink, you agree to these Terms.',
    ],
  },
  {
    heading: '1. Subscription and Payment',
    paragraphs: [
      'HospiceLink is offered on a monthly subscription basis. Subscriptions are billed in advance. By subscribing, you authorize We Market Plus to charge your payment method on a recurring monthly basis.',
      'We Market Plus offers a 30-day money-back guarantee for new subscribers. Requests must be submitted to support@wemarketplus.com within 30 days of the initial payment. After 30 days, subscriptions are non-refundable.',
      'If a payment fails, we will notify you and attempt to process payment again. After multiple failed attempts, your account may be suspended. You can reactivate at any time by updating your payment method.',
    ],
  },
  {
    heading: '2. Account Responsibilities',
    paragraphs: [
      'You are responsible for maintaining the confidentiality of your account credentials. You agree to notify us immediately of any unauthorized use of your account at support@wemarketplus.com.',
      'You are responsible for ensuring that all users on your account comply with applicable laws including HIPAA. Each user must have a unique login — sharing credentials is prohibited.',
    ],
  },
  {
    heading: '3. HIPAA and PHI',
    paragraphs: [
      'HospiceLink is designed to store and process Protected Health Information (PHI) as defined by HIPAA. Before entering any PHI, you must execute a Business Associate Agreement (BAA) with We Market Plus. By activating your account through our post-checkout setup flow, you electronically execute a BAA.',
      'You represent that you are a HIPAA Covered Entity or Business Associate authorized to handle PHI for the patients whose information you enter into HospiceLink. You are responsible for ensuring you have all necessary patient authorizations required by applicable law.',
    ],
  },
  {
    heading: '4. Acceptable Use',
    paragraphs: ['You agree not to:'],
    list: [
      "Use HospiceLink to store PHI for patients not under your organization's care",
      'Attempt to circumvent authentication or access controls',
      'Use HospiceLink for any unlawful purpose',
      'Transmit malware, viruses, or other harmful code',
      'Scrape or bulk-export data for competitive intelligence',
      'Share your subscription with organizations other than your own',
    ],
  },
  {
    heading: '5. Data Ownership',
    paragraphs: [
      'You retain all ownership rights to data you enter into HospiceLink, including PHI. We Market Plus claims no ownership of your data. Upon termination, you may export your data at any time through your account settings.',
    ],
  },
  {
    heading: '6. Service Availability',
    paragraphs: [
      'We Market Plus targets 99.5% monthly uptime but does not guarantee uninterrupted service. We will provide advance notice of planned maintenance when possible. We are not liable for damages arising from service interruptions beyond our reasonable control.',
    ],
  },
  {
    heading: '7. Limitation of Liability',
    paragraphs: [
      'TO THE MAXIMUM EXTENT PERMITTED BY LAW, WE MARKET PLUS SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING LOST PROFITS, LOSS OF DATA, OR HIPAA PENALTIES ARISING FROM YOUR USE OF HOSPICELINK. OUR TOTAL LIABILITY SHALL NOT EXCEED THE AMOUNT PAID BY YOU IN THE 12 MONTHS PRECEDING THE CLAIM.',
    ],
  },
  {
    heading: '8. Termination',
    paragraphs: [
      'Either party may terminate the subscription at any time. Upon termination, your account will be deactivated. Your data will be retained for 90 days to allow for export, after which it will be permanently and irreversibly deleted.',
      'We may terminate or suspend your account immediately if you violate these Terms, fail to pay fees, or engage in conduct harmful to other users or the platform.',
    ],
  },
  {
    heading: '9. Modifications',
    paragraphs: [
      'We may update these Terms from time to time. We will provide at least 30 days notice of material changes via email. Continued use of HospiceLink after the effective date constitutes acceptance of the updated Terms.',
    ],
  },
  {
    heading: '10. Governing Law',
    paragraphs: [
      'These Terms are governed by the laws of the State of Texas, without regard to its conflict of law provisions. Disputes shall be resolved through binding arbitration in Houston, Texas, except that either party may seek injunctive relief in any court of competent jurisdiction.',
    ],
  },
  {
    heading: '11. Contact',
    paragraphs: [
      'We Market Plus LLC — Email: legal@wemarketplus.com — Support: support@wemarketplus.com',
    ],
  },
];

// BAA body — verbatim from "sign baa". Reused by the onboarding wizard.
export const BAA_PARAGRAPHS: readonly string[] = [
  'This Business Associate Agreement ("BAA") is entered into between We Market Plus LLC ("Business Associate") and the subscribing organization ("Covered Entity") pursuant to the Health Insurance Portability and Accountability Act of 1996 (HIPAA) and its implementing regulations at 45 CFR Parts 160 and 164.',
  '1. Definitions. Terms used but not otherwise defined shall have the same meaning as those terms in 45 CFR Parts 160 and 164.',
  '2. Obligations of Business Associate. We Market Plus LLC agrees to: (a) Not use or disclose PHI other than as permitted by this BAA or as required by law; (b) Use appropriate safeguards and implement HIPAA Security Rule requirements to prevent unauthorized use or disclosure of PHI; (c) Report any unauthorized use or disclosure to Covered Entity within 60 calendar days of discovery; (d) Ensure that any subcontractors who create, receive, maintain, or transmit PHI agree to the same restrictions; (e) Make available PHI necessary to satisfy Covered Entity obligations under 45 CFR 164.524; (f) Return or destroy all PHI at termination of this Agreement.',
  '3. Permitted Uses. Business Associate may use or disclose PHI as necessary to provide the HospiceLink CRM services, and as required by law.',
  '4. Term and Termination. This BAA is effective upon electronic signature and terminates when all PHI is returned or destroyed, or upon termination of the underlying service agreement.',
  '5. Miscellaneous. This BAA is governed by the laws of the State of Texas. It shall be amended only in writing. The parties agree that an electronic signature constitutes a legally binding signature for purposes of this Agreement.',
];
