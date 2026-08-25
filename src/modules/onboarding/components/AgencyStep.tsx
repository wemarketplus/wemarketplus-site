import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm } from 'react-hook-form';
import { Button, Input, Label, ListboxSelect } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import { US_STATE_OPTIONS } from '../constants/onboardingConstants';
import {
  agencyInfoSchema,
  type AgencyInfoFormValues,
} from '../schema/onboardingSchema';

export function AgencyStep() {
  const { draft, next, back, saveAgency } = useOnboarding();
  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<AgencyInfoFormValues>({
    resolver: zodResolver(agencyInfoSchema),
    defaultValues: {
      agencyName: draft.agency.agencyName ?? '',
      city: draft.agency.city ?? '',
      state: draft.agency.state ?? '',
      phone: draft.agency.phone ?? '',
      marketerCount: draft.agency.marketerCount ?? 1,
    },
  });

  return (
    <form
      onSubmit={handleSubmit((v) => {
        saveAgency(v);
        next();
      })}
      className="space-y-5"
      noValidate
    >
      <div className="space-y-1.5">
        <Label htmlFor="agencyName">Agency name</Label>
        <Input id="agencyName" autoComplete="organization" {...register('agencyName')} />
        {errors.agencyName && (
          <p className="text-xs text-destructive">{errors.agencyName.message}</p>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="space-y-1.5 sm:col-span-2">
          <Label htmlFor="city">City</Label>
          <Input id="city" autoComplete="address-level2" {...register('city')} />
          {errors.city && (
            <p className="text-xs text-destructive">{errors.city.message}</p>
          )}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="state">State</Label>
          {/*
            A <ListboxSelect>, not a <Select>: 51 options in a native select open
            as a browser-drawn list tall enough to cover the wizard's progress
            steps above this form. See ListboxSelect for the full note. Controller
            rather than register(), since the control is not a form element RHF
            can attach a ref to.
          */}
          <Controller
            control={control}
            name="state"
            render={({ field }) => (
              <ListboxSelect
                id="state"
                value={field.value ?? ''}
                onChange={field.onChange}
                onBlur={field.onBlur}
                options={US_STATE_OPTIONS}
                placeholder="Select a state…"
                invalid={Boolean(errors.state)}
              />
            )}
          />
          {errors.state && (
            <p className="text-xs text-destructive">{errors.state.message}</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="phone">Phone</Label>
          <Input id="phone" type="tel" autoComplete="tel" {...register('phone')} />
          {errors.phone && (
            <p className="text-xs text-destructive">{errors.phone.message}</p>
          )}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="marketerCount">Marketers</Label>
          <Input
            id="marketerCount"
            type="number"
            min={1}
            max={500}
            {...register('marketerCount', { valueAsNumber: true })}
          />
          {errors.marketerCount && (
            <p className="text-xs text-destructive">
              {errors.marketerCount.message}
            </p>
          )}
        </div>
      </div>

      <div className="flex justify-between">
        {/*
          `size="lg"` to match the Continue beside it (h-12); the default `md` is
          h-11, so the footer's two controls sat a pixel off each other. The BAA
          step's footer now carries the same pairing — these two are the app's
          only wizard Back buttons, so they are sized and toned alike.
        */}
        <Button type="button" variant="outline" size="lg" onClick={back}>
          Back
        </Button>
        <Button type="submit" size="lg">Continue</Button>
      </div>
    </form>
  );
}
