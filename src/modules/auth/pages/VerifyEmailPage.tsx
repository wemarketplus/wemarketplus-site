import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Link, useSearchParams } from 'react-router-dom';
import { Loader2, MailX } from 'lucide-react';
import { Button, Input } from '@/shared/ui/core';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthField } from '../components/AuthField';
import { useResendVerification } from '../hooks/useResendVerification';
import { useVerifyEmail } from '../hooks/useVerifyEmail';
import {
  resendVerificationSchema,
  type ResendVerificationFormValues,
} from '../schema/authSchema';

// Landing page for the verification link emailed after registration. The
// ?token= is consumed automatically on mount; success stores the returned
// session and forwards to /billing (plan picker). Failure — expired, reused,
// or malformed token — offers to resend a fresh link.
export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const token = params.get('token');
  const { status } = useVerifyEmail(token);
  const { resend, isLoading: isResending } = useResendVerification();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ResendVerificationFormValues>({
    resolver: zodResolver(resendVerificationSchema),
    defaultValues: { email: '' },
  });

  if (!token) {
    return (
      <AuthCardShell title="Verify Your Email" maxWidth={440} hideFooter>
        <div className="py-5 text-center">
          <MailX className="mx-auto mb-3 h-10 w-10 text-destructive" />
          <h3 className="mb-2 font-extrabold text-destructive">
            Missing Verification Link
          </h3>
          <p className="text-[13px] leading-relaxed text-muted">
            This page needs the verification link from your email.
            <br />
            Open the most recent email we sent you and click the button inside.
          </p>
          <p className="mt-4">
            <Link to="/login" className="font-bold text-azure no-underline hover:underline">
              ← Back to login
            </Link>
          </p>
        </div>
      </AuthCardShell>
    );
  }

  if (status === 'verifying') {
    return (
      <AuthCardShell title="Verify Your Email" maxWidth={440} hideFooter>
        <div className="flex items-center justify-center gap-2.5 py-8 text-[13px] text-muted">
          <Loader2 className="h-4 w-4 animate-spin text-azure" />
          Verifying your email…
        </div>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell
      title="Verification Failed"
      description="This verification link is invalid, expired, or was already used. Enter your email and we'll send you a fresh one."
      maxWidth={440}
    >
      <form onSubmit={handleSubmit((v) => resend(v.email))} noValidate>
        <AuthField label="Email Address" htmlFor="email" error={errors.email?.message}>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            placeholder="you@agency.com"
            {...register('email')}
          />
        </AuthField>
        <Button type="submit" variant="primary" size="block" className="mt-2" disabled={isResending}>
          {isResending ? 'Sending…' : 'Resend Verification Email'}
        </Button>
        <div className="mt-4 text-center text-[13px] text-muted">
          <Link to="/login" className="font-bold text-azure no-underline hover:underline">
            ← Back to login
          </Link>
        </div>
      </form>
    </AuthCardShell>
  );
}
