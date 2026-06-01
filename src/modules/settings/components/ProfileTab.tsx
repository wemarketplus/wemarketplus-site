import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Card, CardContent, Input, Label } from '@/shared/ui/core';
import { useProfileForm } from '../hooks/useProfileForm';
import {
  profileSchema,
  type ProfileFormValues,
} from '../schema/profileSchema';

export function ProfileTab() {
  const { initialValues, submit, isLoading } = useProfileForm();
  const {
    register,
    handleSubmit,
    formState: { errors, isDirty },
    reset,
  } = useForm<ProfileFormValues>({
    resolver: zodResolver(profileSchema),
    defaultValues: initialValues,
  });

  return (
    <Card>
      <CardContent className="px-6 py-6">
        <header className="mb-6">
          <h2 className="text-base font-semibold text-foreground">Profile</h2>
          <p className="mt-1 text-sm text-muted">
            How your name and email appear across the workspace.
          </p>
        </header>

        <form
          onSubmit={handleSubmit(async (v) => {
            await submit(v);
            reset(v);
          })}
          className="space-y-5"
          noValidate
        >
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="firstName">First name</Label>
              <Input id="firstName" {...register('firstName')} />
              {errors.firstName && (
                <p className="text-xs text-destructive">
                  {errors.firstName.message}
                </p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="lastName">Last name</Label>
              <Input id="lastName" {...register('lastName')} />
              {errors.lastName && (
                <p className="text-xs text-destructive">
                  {errors.lastName.message}
                </p>
              )}
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" {...register('email')} />
            {errors.email && (
              <p className="text-xs text-destructive">{errors.email.message}</p>
            )}
          </div>

          <div className="flex items-center justify-end gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={() => reset(initialValues)}
              disabled={!isDirty || isLoading}
            >
              Reset
            </Button>
            <Button type="submit" disabled={!isDirty || isLoading}>
              {isLoading ? 'Saving…' : 'Save changes'}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
