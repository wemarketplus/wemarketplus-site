import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import { Button, PasswordInput } from '@/shared/ui/core';
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
export function ChangePasswordPage() {
  const navigate = useNavigate();
  const { submit, isLoading } = useChangePassword();

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
      title="Change Your Password"
      description="Create a new password to secure your account."
      maxWidth={440}
    >
      <form
        onSubmit={handleSubmit(({ currentPassword, password: next }) =>
          submit({ currentPassword, password: next }, () => {
            reset();
            navigate('/login');
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
