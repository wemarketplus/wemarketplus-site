import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { Button, Input } from '@/shared/ui/core';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthField } from '../components/AuthField';
import { useForgotPassword } from '../hooks/useForgotPassword';
import {
  forgotPasswordSchema,
  type ForgotPasswordFormValues,
} from '../schema/authSchema';

// Mirrors wemarketplus-site/forgot-password.html — including the 📧 success
// box shown after submit (enumeration-safe: always shows success).
export function ForgotPasswordPage() {
  const { submit, submitted, isLoading } = useForgotPassword();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ForgotPasswordFormValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: '' },
  });

  if (submitted) {
    return (
      <AuthCardShell title="Forgot your password?" hideFooter>
        <div className="rounded-[14px] border border-success/30 bg-success/[0.07] p-6 text-center">
          <div className="mb-2.5 text-[36px]">📧</div>
          <h3 className="mb-2 text-[17px] font-extrabold text-success">
            Check Your Email
          </h3>
          <p className="mb-4 text-[13px] leading-relaxed text-muted-soft">
            If that email is registered, we've sent a password reset link.
            <br />
            Check your inbox (and spam folder) and click the link within 1 hour.
          </p>
          <Link
            to="/login"
            className="inline-block rounded-pill bg-primary px-6 py-2.5 text-[14px] font-extrabold text-primary-foreground no-underline"
          >
            Back to Login
          </Link>
        </div>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell
      title="Forgot your password?"
      description="Enter your account email address and we'll send you a link to reset your password. The link is valid for 1 hour."
    >
      <form onSubmit={handleSubmit(submit)} noValidate>
        <AuthField label="Email Address" htmlFor="email" error={errors.email?.message}>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            placeholder="you@agency.com"
            {...register('email')}
          />
        </AuthField>
        <Button type="submit" variant="primary" size="block" className="mt-2" disabled={isLoading}>
          {isLoading ? 'Sending…' : 'Send Reset Link →'}
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
