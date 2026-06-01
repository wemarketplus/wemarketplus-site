import { Link } from 'react-router-dom';
import { Button } from '@/shared/ui/core';
import { LegalShell } from '../components/LegalShell';
import { BAA_PARAGRAPHS } from '../constants/legalContent';

// Mirrors "sign baa": the BAA legal text + a HIPAA-requirement callout. The
// actual signing happens in the onboarding wizard (where the signature +
// password fields live), so this public page presents the agreement and
// routes into onboarding.
export function SignBaaPage() {
  return (
    <LegalShell eyebrow="Compliance" title="Business Associate Agreement">
      <div className="rounded-[12px] border border-azure/20 bg-azure/[0.07] p-4">
        <p className="text-[13px] leading-relaxed text-muted">
          <span className="font-bold text-azure">HIPAA Requirement:</span> A signed
          Business Associate Agreement (BAA) is legally required before you may enter
          any patient health information (PHI) into HospiceLink. It is signed during
          onboarding, where the right administrator captures the electronic signature.
        </p>
      </div>

      <div className="mt-6 space-y-3">
        {BAA_PARAGRAPHS.map((p, i) => (
          <p key={i} className="text-[13px] leading-relaxed text-muted">
            {p}
          </p>
        ))}
      </div>

      <div className="mt-6 flex flex-wrap gap-2">
        <Link to="/onboarding">
          <Button>Start onboarding &amp; sign</Button>
        </Link>
        <Link to="/login">
          <Button variant="secondary">Sign in</Button>
        </Link>
      </div>
    </LegalShell>
  );
}
