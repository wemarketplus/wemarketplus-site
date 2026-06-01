import { LegalShell } from '../components/LegalShell';

// Public compliance overview — distinct from the authenticated audit-log
// screen at /compliance/audit (modules/compliance/pages/CompliancePage).
export function CompliancePublicPage() {
  return (
    <LegalShell eyebrow="Security" title="Compliance posture">
      <p>
        WeMarketPlus is designed for HIPAA-regulated workflows. We follow the
        HIPAA Security Rule's administrative, physical, and technical
        safeguards as a Business Associate to every customer who handles PHI.
      </p>
      <p>
        <span className="font-semibold text-foreground">Encryption.</span> All
        data is encrypted in transit (TLS 1.3) and at rest (AES-256).
      </p>
      <p>
        <span className="font-semibold text-foreground">Access control.</span>{' '}
        Role-based access with least-privilege defaults; every privileged
        action is recorded in the per-tenant audit log.
      </p>
      <p>
        <span className="font-semibold text-foreground">Incident response.</span>{' '}
        Documented IR process, 60-day breach-notification commitment, and
        annual third-party audits.
      </p>
      <p className="text-xs text-muted-soft">
        Need our SOC 2 report or sample audit log? Email{' '}
        <a className="text-primary" href="mailto:security@wemarketplus.com">
          security@wemarketplus.com
        </a>
        .
      </p>
    </LegalShell>
  );
}
