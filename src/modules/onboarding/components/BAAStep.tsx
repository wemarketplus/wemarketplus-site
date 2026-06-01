import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { setCredentials } from '@/modules/auth';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { Button, Input, Label } from '@/shared/ui/core';
import { useOnboardMutation } from '../api/onboardingApi';
import { useOnboarding } from '../hooks/useOnboarding';
import { baaSchema, type BAAFormValues } from '../schema/onboardingSchema';
import type {
  AccountInfo,
  AgencyInfo,
  OnboardRequest,
} from '../types/onboardingTypes';

export function BAAStep() {
  const { draft, next, back, saveBAA, markCompleted } = useOnboarding();
  const dispatch = useAppDispatch();
  const [onboard, state] = useOnboardMutation();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<BAAFormValues>({
    resolver: zodResolver(baaSchema),
    defaultValues: {
      signature: draft.baa.signature ?? '',
      title: draft.baa.title ?? '',
      acknowledged: draft.baa.acknowledged ?? false,
    },
  });

  return (
    <form
      onSubmit={handleSubmit(async (v) => {
        saveBAA(v);
        // Earlier steps must be complete to call onboard. If we don't have them,
        // bail to step 1 — there's nothing else this hook can do without them.
        if (
          !draft.account.email ||
          !draft.account.password ||
          !draft.agency.agencyName
        ) {
          toast.error('Please finish the earlier steps before signing.');
          return;
        }
        const payload: OnboardRequest = {
          account: draft.account as AccountInfo,
          agency: draft.agency as AgencyInfo,
          baa: v,
          stripeSessionId: draft.stripeSessionId,
        };
        try {
          const result = await onboard(payload).unwrap();
          dispatch(setCredentials({ token: result.accessToken, user: result.user }));
          markCompleted();
          next();
        } catch (err) {
          toast.error(
            extractApiErrorMessage(err, "Couldn't activate your workspace"),
          );
        }
      })}
      className="space-y-5"
      noValidate
    >
      <div className="max-h-72 overflow-y-auto rounded-md border border-white/[0.06] bg-white/[0.02] p-4 text-sm leading-relaxed text-muted">
        <h3 className="mb-2 font-semibold text-foreground">
          Business Associate Agreement (excerpt)
        </h3>
        <p>
          This Business Associate Agreement (“BAA”) governs the use, disclosure, and
          safeguarding of Protected Health Information (“PHI”) under HIPAA between
          WeMarketPlus, Inc. (“Business Associate”) and the signing organization
          (“Covered Entity”).
        </p>
        <p className="mt-3">
          Business Associate will: (a) use and disclose PHI only as permitted under
          this BAA or required by law; (b) safeguard PHI in accordance with the
          Security Rule (45 CFR §§ 164.308, 310, 312); (c) report breaches in
          writing within 60 days; (d) make PHI available for amendment, accounting,
          and access; and (e) return or destroy PHI upon termination.
        </p>
        <p className="mt-3 text-xs text-muted-soft">
          Full BAA text and supplementary HIPAA documentation are available at
          /compliance after sign-in.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="signature">Electronic signature (full name)</Label>
          <Input id="signature" {...register('signature')} />
          {errors.signature && (
            <p className="text-xs text-destructive">{errors.signature.message}</p>
          )}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="title">Title / Role</Label>
          <Input id="title" {...register('title')} />
          {errors.title && (
            <p className="text-xs text-destructive">{errors.title.message}</p>
          )}
        </div>
      </div>

      <label className="flex items-start gap-3 text-sm text-foreground">
        <input
          type="checkbox"
          className="mt-0.5 h-4 w-4 rounded border border-white/15 bg-surface-raised text-primary focus:ring-primary/50"
          {...register('acknowledged')}
        />
        <span>
          I have read the BAA above and confirm I am authorized to sign on behalf
          of my organization.
        </span>
      </label>
      {errors.acknowledged && (
        <p className="-mt-3 text-xs text-destructive">
          {errors.acknowledged.message}
        </p>
      )}

      <div className="flex justify-between">
        <Button
          type="button"
          variant="ghost"
          onClick={back}
          disabled={state.isLoading}
        >
          Back
        </Button>
        <Button type="submit" size="lg" disabled={state.isLoading}>
          {state.isLoading ? 'Activating…' : 'Sign & launch'}
        </Button>
      </div>
    </form>
  );
}
