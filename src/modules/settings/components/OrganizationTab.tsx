import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { Button, Card, CardContent, Input, Label } from '@/shared/ui/core';
import { useOrganizationForm } from '../hooks/useOrganizationForm';
import {
  organizationSchema,
  type OrganizationFormValues,
} from '../schema/organizationSchema';
import { US_STATES } from '@/modules/onboarding/constants/onboardingConstants';
import { REPORT_TIMEZONE_OPTIONS } from '../constants/settingsConstants';
import { cn } from '@/shared/utils/cn';

export function OrganizationTab() {
  const {
    initialValues,
    submit,
    isLoading,
    isError,
    refetch,
    isSaving,
    loaded,
  } = useOrganizationForm();

  const {
    register,
    handleSubmit,
    formState: { errors, isDirty },
    reset,
  } = useForm<OrganizationFormValues>({
    resolver: zodResolver(organizationSchema),
    defaultValues: initialValues,
  });

  // RHF captures defaultValues once at mount; hydrate the form when the
  // tenant profile arrives (or changes) so fields reflect the server state.
  useEffect(() => {
    if (loaded) {
      reset(initialValues);
    }
  }, [loaded, initialValues, reset]);

  const busy = isLoading || isSaving;

  return (
    <Card>
      <CardContent className="px-6 py-6">
        <header className="mb-6">
          <h2 className="text-base font-semibold text-foreground">Organization</h2>
          <p className="mt-1 text-sm text-muted">
            Brand and contact details that appear on referral materials.
          </p>
        </header>

        {isError ? (
          <div className="flex flex-col items-start gap-3 rounded-lg border border-border/[0.06] bg-foreground/[0.02] px-4 py-4">
            <p className="text-sm text-muted">
              Couldn&apos;t load your organization profile.
            </p>
            <Button size="sm" variant="secondary" onClick={() => refetch()}>
              Retry
            </Button>
          </div>
        ) : (
          <form
            onSubmit={handleSubmit(async (v) => {
              const ok = await submit(v);
              if (ok) {
                reset(v);
              }
            })}
            className="space-y-5"
            noValidate
          >
            <div className="space-y-1.5">
              <Label htmlFor="orgName">Agency / organization name</Label>
              <Input id="orgName" disabled={busy} {...register('name')} />
              {errors.name && (
                <p className="text-xs text-destructive">{errors.name.message}</p>
              )}
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="orgCity">City</Label>
                <Input id="orgCity" disabled={busy} {...register('city')} />
                {errors.city && (
                  <p className="text-xs text-destructive">{errors.city.message}</p>
                )}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="orgState">State</Label>
                <select
                  id="orgState"
                  disabled={busy}
                  {...register('state')}
                  className={cn(
                    'flex h-11 w-full rounded-md border border-border/10 bg-surface-raised px-3 text-sm text-foreground',
                    'transition-colors focus-visible:outline-none focus-visible:border-azure/70 focus-visible:bg-surface',
                    'disabled:cursor-not-allowed disabled:opacity-60',
                  )}
                >
                  <option value="">—</option>
                  {US_STATES.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.value}
                    </option>
                  ))}
                </select>
                {errors.state && (
                  <p className="text-xs text-destructive">{errors.state.message}</p>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="orgPhone">Phone</Label>
              <Input
                id="orgPhone"
                type="tel"
                disabled={busy}
                {...register('phone')}
              />
              {errors.phone && (
                <p className="text-xs text-destructive">{errors.phone.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="orgReportTimezone">Report time zone</Label>
              <select
                id="orgReportTimezone"
                disabled={busy}
                {...register('reportTimezone')}
                className={cn(
                  'flex h-11 w-full rounded-md border border-border/10 bg-surface-raised px-3 text-sm text-foreground',
                  'transition-colors focus-visible:outline-none focus-visible:border-azure/70 focus-visible:bg-surface',
                  'disabled:cursor-not-allowed disabled:opacity-60',
                )}
              >
                {REPORT_TIMEZONE_OPTIONS.map((tz) => (
                  <option key={tz.value} value={tz.value}>
                    {tz.label}
                  </option>
                ))}
              </select>
              <p className="text-xs text-muted">
                Scheduled reports are timed against this zone. The Weekly Report is
                emailed to administrators every Monday at 7:00&nbsp;AM local time.
              </p>
              {errors.reportTimezone && (
                <p className="text-xs text-destructive">
                  {errors.reportTimezone.message}
                </p>
              )}
            </div>

            <div className="flex items-center justify-end gap-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() => reset(initialValues)}
                disabled={!isDirty || busy}
              >
                Reset
              </Button>
              <Button type="submit" disabled={!isDirty || busy}>
                {isSaving ? 'Saving…' : 'Save changes'}
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
