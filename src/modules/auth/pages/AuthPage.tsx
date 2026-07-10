import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { Button, Input, PasswordInput } from '@/shared/ui/core';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthError } from '../components/AuthError';
import { AuthField } from '../components/AuthField';
import { useLogin } from '../hooks/useLogin';
import { loginSchema, type LoginFormValues } from '../schema/authSchema';

// Mirrors wemarketplus-site/login.html exactly: title "Welcome back",
// sub "Sign in to your CRM account", email + password fields, right-aligned
// forgot link, full-width azure "Sign In" pill, "View Plans" message.
// When the account has TOTP MFA enabled, login returns { mfaRequired } and the
// page swaps to a 6-digit code step before completing sign-in.
export function AuthPage() {
  const {
    submit,
    isLoading,
    unverifiedEmail,
    resendVerification,
    isResending,
    mfaRequired,
    submitMfaCode,
    cancelMfa,
    isVerifyingMfa,
  } = useLogin();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });
  const [code, setCode] = useState('');

  if (mfaRequired) {
    return (
      <AuthCardShell
        title="Two-factor authentication"
        description="Enter the 6-digit code from your authenticator app"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submitMfaCode(code);
          }}
          noValidate
        >
          <AuthField label="Authentication code" htmlFor="mfa-code">
            <Input
              id="mfa-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            />
          </AuthField>
          <Button
            type="submit"
            variant="primary"
            size="block"
            className="mt-2"
            disabled={isVerifyingMfa || code.length !== 6}
          >
            {isVerifyingMfa ? 'Verifying…' : 'Verify'}
          </Button>
          <div className="mt-5 text-center text-[13px] text-muted">
            <button
              type="button"
              onClick={() => {
                setCode('');
                cancelMfa();
              }}
              className="font-bold text-azure no-underline hover:underline"
            >
              Back to sign in
            </button>
          </div>
        </form>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell title="Welcome back" description="Sign in to your CRM account">
      <form onSubmit={handleSubmit(submit)} noValidate>
        {unverifiedEmail && (
          <AuthError>
            Please verify your email address first.{' '}
            <button
              type="button"
              onClick={resendVerification}
              disabled={isResending}
              className="font-bold text-azure underline underline-offset-2 disabled:opacity-50"
            >
              {isResending ? 'Sending…' : 'Resend verification email'}
            </button>
          </AuthError>
        )}
        <AuthField label="Email Address" htmlFor="email" error={errors.email?.message}>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            placeholder="you@agency.com"
            {...register('email')}
          />
        </AuthField>

        <AuthField
          label="Password"
          htmlFor="password"
          error={errors.password?.message}
          helper={
            <Link
              to="/forgot-password"
              className="text-[12px] text-azure no-underline hover:underline"
            >
              Forgot password?
            </Link>
          }
        >
          <PasswordInput
            id="password"
            autoComplete="current-password"
            placeholder="••••••••"
            {...register('password')}
          />
        </AuthField>

        <Button type="submit" variant="primary" size="block" className="mt-2" disabled={isLoading}>
          {isLoading ? 'Signing in…' : 'Sign In'}
        </Button>

        <div className="mt-5 text-center text-[13px] text-muted">
          Don't have an account?{' '}
          <Link to="/pricing" className="font-bold text-azure no-underline hover:underline">
            View Plans
          </Link>
        </div>
      </form>
    </AuthCardShell>
  );
}
