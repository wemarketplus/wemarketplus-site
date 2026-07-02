import { Check, MailCheck, Rocket } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/shared/ui/core';
import { useResendVerification } from '@/modules/auth';
import { useOnboarding } from '../hooks/useOnboarding';

const CHECKLIST = [
  'Admin account created',
  'Organization profile saved',
  'Business Associate Agreement signed',
  'Role-based access control initialized',
  'HIPAA audit logging enabled',
  'Workspace encryption keys provisioned',
];

export function LaunchStep() {
  const navigate = useNavigate();
  const { pendingVerificationEmail } = useOnboarding();
  const { resend, isLoading: isResending } = useResendVerification();

  // Production path: the account was created but the backend withheld tokens
  // until the emailed verification link is clicked — so instead of "You're
  // live", tell the owner to go check their inbox.
  if (pendingVerificationEmail) {
    return (
      <div className="space-y-6 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-primary/15 text-primary ring-1 ring-primary/30">
          <MailCheck className="h-6 w-6" />
        </div>
        <div className="space-y-1">
          <h2 className="font-display text-3xl text-foreground">Check your email</h2>
          <p className="text-sm text-muted">
            We sent a verification link to{' '}
            <span className="font-semibold text-foreground">
              {pendingVerificationEmail}
            </span>
            .
            <br />
            Click it to verify your address and activate your workspace.
          </p>
        </div>
        <Button
          size="lg"
          variant="secondary"
          onClick={() => resend(pendingVerificationEmail)}
          disabled={isResending}
        >
          {isResending ? 'Sending…' : 'Resend verification email'}
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6 text-center">
      <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-primary/15 text-primary ring-1 ring-primary/30">
        <Rocket className="h-6 w-6" />
      </div>
      <div className="space-y-1">
        <h2 className="font-display text-3xl text-foreground">You're live</h2>
        <p className="text-sm text-muted">
          Your workspace is provisioned and ready to go.
        </p>
      </div>
      <ul className="mx-auto max-w-md space-y-2 text-left">
        {CHECKLIST.map((entry) => (
          <li
            key={entry}
            className="flex items-center gap-2.5 rounded-md border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-sm text-foreground"
          >
            <Check className="h-4 w-4 text-primary" />
            {entry}
          </li>
        ))}
      </ul>
      <Button size="lg" onClick={() => navigate('/', { replace: true })}>
        Launch my CRM
      </Button>
    </div>
  );
}
