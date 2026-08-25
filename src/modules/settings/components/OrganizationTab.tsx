import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { zodResolver } from '@hookform/resolvers/zod';
import { useEffect } from 'react';
import { Controller, useForm } from 'react-hook-form';
import {
  Button,
  Card,
  CardContent,
  Input,
  Label,
  ListboxSelect,
  Select,
} from '@/shared/ui/core';
import { useOrganizationForm } from '../hooks/useOrganizationForm';
import {
  organizationSchema,
  type OrganizationFormValues,
} from '../schema/organizationSchema';
import { US_STATE_OPTIONS } from '@/modules/onboarding/constants/onboardingConstants';
import { REPORT_TIMEZONE_OPTIONS } from '../constants/settingsConstants';

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
    control,
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
          <h2 className={SECTION_TITLE}>Organization</h2>
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

            <div className="space-y-1.5">
              <Label htmlFor="orgAddress">Street address</Label>
              <Input
                id="orgAddress"
                autoComplete="street-address"
                disabled={busy}
                {...register('address')}
              />
              {errors.address && (
                <p className="text-xs text-destructive">
                  {errors.address.message}
                </p>
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
                {/*
                  A <ListboxSelect>, not a native <select>: 51 options open as a
                  browser-drawn list hundreds of pixels tall, which Chrome places
                  upward from this field and straight over the settings tab strip.
                  See ListboxSelect for why no CSS reaches that popup. Controller
                  rather than register(), since the control is not a form element
                  RHF can attach a ref to.
                */}
                <Controller
                  control={control}
                  name="state"
                  render={({ field }) => (
                    <ListboxSelect
                      id="orgState"
                      value={field.value ?? ''}
                      onChange={field.onChange}
                      onBlur={field.onBlur}
                      options={US_STATE_OPTIONS}
                      placeholder="—"
                      disabled={busy}
                      invalid={Boolean(errors.state)}
                    />
                  )}
                />
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
              {/*
                <Select>, not a hand-rolled one. The height matched by luck, but
                nothing else did: `border-border/10` against the field
                language's /.12, `px-3` against `px-3.5`, and — the visible
                one — a focus ring in AZURE while every other field in this same
                form focuses to `primary`. Tabbing through Organization settings
                turned one field blue and the rest green.
              */}
              <Select
                id="orgReportTimezone"
                disabled={busy}
                {...register('reportTimezone')}
              >
                {REPORT_TIMEZONE_OPTIONS.map((tz) => (
                  <option key={tz.value} value={tz.value}>
                    {tz.label}
                  </option>
                ))}
              </Select>
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
              {/*
                `outline`, not `ghost` — the same reasoning as ProfileTab's
                Reset, which this footer is a copy of. Fixed here too because the
                two are the same control in the same resting state (`!isDirty`),
                so leaving this one on `ghost` would have left the reported bug
                alive on the Settings page it is also reachable from.
              */}
              <Button
                type="button"
                variant="outline"
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
