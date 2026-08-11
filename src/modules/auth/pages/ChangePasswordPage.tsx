import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { Button, PasswordInput } from '@/shared/ui/core';
import { logout } from '../store/authSlice';
import { AuthCardShell } from '../components/AuthCardShell';
import { AuthField } from '../components/AuthField';
import { PasswordStrengthMeter } from '../components/PasswordStrengthMeter';
import { useChangePassword } from '../hooks/useChangePassword';
import {
  changePasswordSchema,
  type ChangePasswordFormValues,
} from '../schema/authSchema';

// Mirrors wemarketplus-site/change-password.html — a standalone centered
// auth card (reached when login returns must_change_password). Current +
// new + confirm, strength meter, gradient submit.
//
// Serves both the FORCED change (/change-password, where ProtectedRoute sends a
// user holding an admin-issued password) and the voluntary one from settings
// (/account/password). The form is identical; only the copy below differs, because
// someone who was sent here needs to know why.
export function ChangePasswordPage() {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { submit, isLoading } = useChangePassword();
  const forced = useAppSelector((s) => s.auth.user?.mustChangePassword ?? false);

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors },
  } = useForm<ChangePasswordFormValues>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: { currentPassword: '', password: '', confirmPassword: '' },
  });

  const password = watch('password');

  return (
    <AuthCardShell
      title={forced ? 'Set a new password' : 'Change Your Password'}
      description={
        forced
          ? 'The password you signed in with was issued by an administrator. Choose your own to continue.'
          : 'Create a new password to secure your account.'
      }
      maxWidth={440}
    >
      <form
        onSubmit={handleSubmit(({ currentPassword, password: next }) =>
          submit({ currentPassword, password: next }, () => {
            reset();
            /**
             * Changing a password revokes every session for that user server-side
             * (auth.service.changePassword), so the token this tab is holding is
             * already dead. Clearing it locally is what makes /login render — while
             * the store still says "authenticated", PublicRoute bounces us to "/",
             * which then fails on the revoked token.
             */
            dispatch(logout());
            navigate('/login', { replace: true });
          }),
        )}
        noValidate
      >
        <AuthField
          label="Current Password"
          htmlFor="currentPassword"
          error={errors.currentPassword?.message}
        >
          <PasswordInput
            id="currentPassword"
            autoComplete="current-password"
            placeholder="Enter current password"
            {...register('currentPassword')}
          />
        </AuthField>

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
          {isLoading ? 'Updating…' : 'Update Password →'}
        </Button>
      </form>
    </AuthCardShell>
  );
}
