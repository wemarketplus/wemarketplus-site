import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Link, useSearchParams } from 'react-router-dom';
import { Button, PasswordInput } from '@/shared/ui/core';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthField } from '../components/AuthField';
import { PasswordStrengthMeter } from '../components/PasswordStrengthMeter';
import { useAcceptInvite } from '../hooks/useAcceptInvite';
import {
  acceptInviteSchema,
  type AcceptInviteFormValues,
} from '../schema/authSchema';

// Mirrors the "accept invite" / activate-account flow: strength meter,
// gradient activate button, invalid-token state (72h expiry).
export function AcceptInvitePage() {
  const [params] = useSearchParams();
  const token = params.get('token');
  const { submit, isLoading } = useAcceptInvite(token);

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<AcceptInviteFormValues>({
    resolver: zodResolver(acceptInviteSchema),
    defaultValues: { password: '', confirmPassword: '' },
  });

  const password = watch('password');

  if (!token) {
    return (
      <AuthCardShell title="Activate Your Account" maxWidth={440} hideFooter>
        <div className="py-5 text-center">
          <div className="mb-3 text-[40px]">🔗</div>
          <h3 className="mb-2 font-extrabold text-destructive">
            Invalid or Expired Invitation
          </h3>
          <p className="text-[13px] leading-relaxed text-muted">
            Invitation links expire 72 hours after they're sent.
            <br />
            Ask your administrator for a fresh invitation.
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

  return (
    <AuthCardShell
      title="Activate Your Account"
      description="Choose a strong password to finish setting up your account."
      maxWidth={440}
    >
      <form onSubmit={handleSubmit((v) => submit(v.password))} noValidate>
        <AuthField label="New Password" htmlFor="password" error={errors.password?.message}>
          <PasswordInput
            id="password"
            autoComplete="new-password"
            placeholder="Create a strong password"
            {...register('password')}
          />
          <PasswordStrengthMeter value={password} />
        </AuthField>

        <AuthField
          label="Confirm New Password"
          htmlFor="confirmPassword"
          error={errors.confirmPassword?.message}
        >
          <PasswordInput
            id="confirmPassword"
            autoComplete="new-password"
            placeholder="Re-enter your new password"
            {...register('confirmPassword')}
          />
        </AuthField>

        <Button type="submit" variant="gradient" size="block" className="mt-2" disabled={isLoading}>
          {isLoading ? 'Activating…' : 'Activate My Account →'}
        </Button>
      </form>
    </AuthCardShell>
  );
}
