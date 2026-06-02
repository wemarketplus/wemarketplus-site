import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, PasswordInput } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import { WizardField } from './WizardField';
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
        <WizardField
          label="First name"
          htmlFor="firstName"
          error={errors.firstName?.message}
        >
          <Input id="firstName" autoComplete="given-name" {...register('firstName')} />
        </WizardField>
        <WizardField
          label="Last name"
          htmlFor="lastName"
          error={errors.lastName?.message}
        >
          <Input id="lastName" autoComplete="family-name" {...register('lastName')} />
        </WizardField>
      </div>
      <WizardField label="Work email" htmlFor="email" error={errors.email?.message}>
        <Input id="email" type="email" autoComplete="email" {...register('email')} />
      </WizardField>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <WizardField label="Password" htmlFor="password" error={errors.password?.message}>
          <PasswordInput
            id="password"
            autoComplete="new-password"
            {...register('password')}
          />
        </WizardField>
        <WizardField
          label="Confirm password"
          htmlFor="confirmPassword"
          error={errors.confirmPassword?.message}
        >
          <PasswordInput
            id="confirmPassword"
            autoComplete="new-password"
            {...register('confirmPassword')}
          />
        </WizardField>
      </div>

      <div className="flex justify-end">
        <Button type="submit" size="lg">Continue</Button>
      </div>
    </form>
  );
}
