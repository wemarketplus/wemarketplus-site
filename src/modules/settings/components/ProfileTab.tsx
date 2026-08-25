import { SECTION_TITLE } from '@/shared/ui/core/typography';
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
          <h2 className={SECTION_TITLE}>Profile</h2>
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
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" {...register('email')} />
              {errors.email && (
                <p className="text-xs text-destructive">
                  {errors.email.message}
                </p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="phone">Phone</Label>
              <Input id="phone" type="tel" {...register('phone')} />
              {errors.phone && (
                <p className="text-xs text-destructive">
                  {errors.phone.message}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center justify-end gap-2">
            {/*
              `outline`, not `ghost`. Reset is a NAMED action in a form footer,
              and `ghost` gives a named action no affordance at all: no fill, no
              border, and `text-muted` for its only signal. Because the footer's
              resting state is `!isDirty` — what every visitor to this page sees
              before touching a field — `disabled:opacity-50` then halves that one
              signal, taking the label to 1.98:1 against the white card. It stops
              reading as a button and reads as a stray grey word, which is the
              "Reset button has low visibility, making it difficult to identify"
              report. `outline` keeps it quiet (transparent fill, weight 600,
              still plainly subordinate to the filled Save) while giving it the
              two things that survive being dimmed: a pill border, so the control
              has a SHAPE even when disabled, and `text-foreground` instead of
              muted grey.

              `ghost` stays right where the surrounding context supplies the
              affordance — icon buttons, and the Cancel in a dialog footer that
              is bounded by the dialog itself.
            */}
            <Button
              type="button"
              variant="outline"
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
