import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import { US_STATES } from '../constants/onboardingConstants';
import {
  agencyInfoSchema,
  type AgencyInfoFormValues,
} from '../schema/onboardingSchema';
import { cn } from '@/shared/utils/cn';

export function AgencyStep() {
  const { draft, next, back, saveAgency } = useOnboarding();
  const {
    register,
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
        <Input id="agencyName" {...register('agencyName')} />
        {errors.agencyName && (
          <p className="text-xs text-destructive">{errors.agencyName.message}</p>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="space-y-1.5 sm:col-span-2">
          <Label htmlFor="city">City</Label>
          <Input id="city" {...register('city')} />
          {errors.city && (
            <p className="text-xs text-destructive">{errors.city.message}</p>
          )}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="state">State</Label>
          <select
            id="state"
            className={cn(
              'flex h-11 w-full rounded-md border border-white/10 bg-surface-raised px-3 text-sm text-foreground',
              'transition-colors focus-visible:outline-none focus-visible:border-azure/70 focus-visible:bg-surface',
            )}
            {...register('state')}
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

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="phone">Phone</Label>
          <Input id="phone" type="tel" {...register('phone')} />
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
        <Button type="button" variant="ghost" onClick={back}>
          Back
        </Button>
        <Button type="submit" size="lg">Continue</Button>
      </div>
    </form>
  );
}
