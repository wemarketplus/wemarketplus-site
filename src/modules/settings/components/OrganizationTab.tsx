import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { Button, Card, CardContent, Input, Label } from '@/shared/ui/core';
import {
  organizationSchema,
  type OrganizationFormValues,
} from '../schema/organizationSchema';
import { US_STATES } from '@/modules/onboarding/constants/onboardingConstants';
import { cn } from '@/shared/utils/cn';

// TODO(backend): wire to /organizations when it ships. Today this form
// validates locally and toasts on submit so the screen is interactive.
const PLACEHOLDER_ORG: OrganizationFormValues = {
  name: 'Bay Area Hospice Group',
  city: 'San Francisco',
  state: 'CA',
  phone: '(415) 555-2200',
};

export function OrganizationTab() {
  const {
    register,
    handleSubmit,
    formState: { errors, isDirty },
    reset,
  } = useForm<OrganizationFormValues>({
    resolver: zodResolver(organizationSchema),
    defaultValues: PLACEHOLDER_ORG,
  });

  return (
    <Card>
      <CardContent className="px-6 py-6">
        <header className="mb-6 flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-foreground">Organization</h2>
            <p className="mt-1 text-sm text-muted">
              Brand and contact details that appear on referral materials.
            </p>
          </div>
          <span className="rounded-pill border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[10px] uppercase tracking-[0.08em] text-muted-soft">
            Preview data
          </span>
        </header>

        <form
          onSubmit={handleSubmit((v) => {
            toast.success('Saved (preview only — backend not wired)');
            reset(v);
          })}
          className="space-y-5"
          noValidate
        >
          <div className="space-y-1.5">
            <Label htmlFor="orgName">Agency / organization name</Label>
            <Input id="orgName" {...register('name')} />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name.message}</p>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="orgCity">City</Label>
              <Input id="orgCity" {...register('city')} />
              {errors.city && (
                <p className="text-xs text-destructive">{errors.city.message}</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="orgState">State</Label>
              <select
                id="orgState"
                {...register('state')}
                className={cn(
                  'flex h-11 w-full rounded-md border border-white/10 bg-surface-raised px-3 text-sm text-foreground',
                  'transition-colors focus-visible:outline-none focus-visible:border-azure/70 focus-visible:bg-surface',
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
            <Input id="orgPhone" type="tel" {...register('phone')} />
            {errors.phone && (
              <p className="text-xs text-destructive">{errors.phone.message}</p>
            )}
          </div>

          <div className="flex items-center justify-end gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={() => reset(PLACEHOLDER_ORG)}
              disabled={!isDirty}
            >
              Reset
            </Button>
            <Button type="submit" disabled={!isDirty}>
              Save changes
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
