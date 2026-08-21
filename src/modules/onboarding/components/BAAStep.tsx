import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Checkbox, Input, Label } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import { useOnboardingSubmit } from '../hooks/useOnboardingSubmit';
import { baaSchema, type BAAFormValues } from '../schema/onboardingSchema';

export function BAAStep() {
  const { draft, back } = useOnboarding();
  const { submitBAA, isSubmitting } = useOnboardingSubmit();

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
      onSubmit={handleSubmit(submitBAA)}
      className="space-y-5"
      noValidate
    >
      <div className="max-h-72 overflow-y-auto rounded-md border border-border/[0.06] bg-foreground/[0.02] p-4 text-sm leading-relaxed text-muted">
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
        <Checkbox className="mt-0.5" {...register('acknowledged')} />
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
        {/*
          `outline`, not `ghost`, and `lg` to match its partner.

          `ghost` is transparent with `text-muted` and no border, which on this
          white card left the only way BACK out of the final signing step reading
          as body copy — 4.95:1 text with nothing around it, no edge to say it
          was a control at all. `outline` gives it a border and foreground text
          (17.29:1) while the fill still belongs to "Sign & launch" alone, so the
          step keeps exactly one primary action. This is the same swap the agency
          step's Back button already carries — those two are the app's only wizard
          Back buttons, so both are now `outline`.

          The size is deliberate as well: the submit beside it is `size="lg"`
          (h-12) and Back defaulted to `md` (h-11), so the footer's two controls
          sat a pixel off each other. The agency step carries the same pairing, so
          the wizard's two Back buttons are sized and toned alike.
        */}
        <Button
          type="button"
          variant="outline"
          size="lg"
          onClick={back}
          disabled={isSubmitting}
        >
          Back
        </Button>
        <Button type="submit" size="lg" disabled={isSubmitting}>
          {isSubmitting ? 'Activating…' : 'Sign & launch'}
        </Button>
      </div>
    </form>
  );
}
