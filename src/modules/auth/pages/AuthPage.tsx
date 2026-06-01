import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { Button, Input, PasswordInput } from '@/shared/ui/core';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthField } from '../components/AuthField';
import { useLogin } from '../hooks/useLogin';
import { loginSchema, type LoginFormValues } from '../schema/authSchema';

// Mirrors wemarketplus-site/login.html exactly: title "Welcome back",
// sub "Sign in to your CRM account", email + password fields, right-aligned
// forgot link, full-width azure "Sign In" pill, "View Plans" message.
export function AuthPage() {
  const { submit, isLoading } = useLogin();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });

  return (
    <AuthCardShell title="Welcome back" description="Sign in to your CRM account">
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
