import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Link, useSearchParams } from 'react-router-dom';
import { Button, PasswordInput } from '@/shared/ui/core';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthField } from '../components/AuthField';
import { PasswordStrengthMeter } from '../components/PasswordStrengthMeter';
import { useResetPassword } from '../hooks/useResetPassword';
import {
  resetPasswordSchema,
  type ResetPasswordFormValues,
} from '../schema/authSchema';

// Mirrors wemarketplus-site/reset-password.html: invalid-token state (🔗),
// strength meter + req-list, gradient "Reset My Password →" button.
export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get('token');
  const { submit, isLoading } = useResetPassword(token);

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<ResetPasswordFormValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { password: '', confirmPassword: '' },
  });

  const password = watch('password');

  if (!token) {
    return (
      <AuthCardShell title="Set New Password" maxWidth={440} hideFooter>
        <div className="py-5 text-center">
          <div className="mb-3 text-[40px]">🔗</div>
          <h3 className="mb-2 font-extrabold text-destructive">
            Invalid or Expired Link
          </h3>
          <p className="text-[13px] leading-relaxed text-muted">
            This password reset link is invalid or has expired.
            <br />
            Reset links are valid for 1 hour.
          </p>
          <p className="mt-4">
            <Link
              to="/forgot-password"
              className="font-bold text-azure no-underline hover:underline"
            >
              Request a new reset link →
            </Link>
          </p>
        </div>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell
      title="Set New Password"
      description="Create a strong password to secure your HIPAA-compliant CRM account."
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
          {isLoading ? 'Resetting…' : 'Reset My Password →'}
        </Button>
      </form>
    </AuthCardShell>
  );
}
