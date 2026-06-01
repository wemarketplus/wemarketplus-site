import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, PasswordInput } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import {
  accountInfoSchema,
  type AccountInfoFormValues,
} from '../schema/onboardingSchema';

export function AccountStep() {
  const { draft, next, saveAccount } = useOnboarding();
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<AccountInfoFormValues>({
    resolver: zodResolver(accountInfoSchema),
    defaultValues: {
      firstName: draft.account.firstName ?? '',
      lastName: draft.account.lastName ?? '',
      email: draft.account.email ?? '',
      password: draft.account.password ?? '',
      confirmPassword: draft.account.password ?? '',
    },
  });

  return (
    <form
      onSubmit={handleSubmit((v) => {
        saveAccount({
          firstName: v.firstName,
          lastName: v.lastName,
          email: v.email,
          password: v.password,
        });
        next();
      })}
      className="space-y-5"
      noValidate
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field
          label="First name"
          id="firstName"
          error={errors.firstName?.message}
        >
          <Input id="firstName" autoComplete="given-name" {...register('firstName')} />
        </Field>
        <Field
          label="Last name"
          id="lastName"
          error={errors.lastName?.message}
        >
          <Input id="lastName" autoComplete="family-name" {...register('lastName')} />
        </Field>
      </div>
      <Field label="Work email" id="email" error={errors.email?.message}>
        <Input id="email" type="email" autoComplete="email" {...register('email')} />
      </Field>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field label="Password" id="password" error={errors.password?.message}>
          <PasswordInput
            id="password"
            autoComplete="new-password"
            {...register('password')}
          />
        </Field>
        <Field
          label="Confirm password"
          id="confirmPassword"
          error={errors.confirmPassword?.message}
        >
          <PasswordInput
            id="confirmPassword"
            autoComplete="new-password"
            {...register('confirmPassword')}
          />
        </Field>
      </div>

      <div className="flex justify-end">
        <Button type="submit" size="lg">Continue</Button>
      </div>
    </form>
  );
}

function Field({
  label,
  id,
  error,
  children,
}: {
  label: string;
  id: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
