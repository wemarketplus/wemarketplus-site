import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Card, CardContent, Logo } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import { STEP_LABELS } from '../constants/onboardingConstants';
import { setPendingPlan } from '../utils/pendingPlan';
import { WizardProgress } from '../components/WizardProgress';
import { AccountStep } from '../components/AccountStep';
import { AgencyStep } from '../components/AgencyStep';
import { BAAStep } from '../components/BAAStep';
import { LaunchStep } from '../components/LaunchStep';

export function OnboardingPage() {
  const { currentStep } = useOnboarding();
  const [searchParams] = useSearchParams();

  // Persist the plan chosen on the pricing page (?plan=<catalogKey>) the moment
  // the wizard mounts, so it survives the email verification round-trip even
  // when the verify link is opened in a fresh tab. Post-verify (and the dev
  // register-with-tokens path) reads this back to jump straight to checkout.
  useEffect(() => {
    const plan = searchParams.get('plan');
    if (plan) setPendingPlan(plan);
  }, [searchParams]);

  return (
    <div className="relative min-h-screen overflow-hidden bg-bg px-4 py-10">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(ellipse 700px 480px at 50% 0%, rgb(var(--color-primary) / 0.08), transparent 60%)',
        }}
      />
      <div className="mx-auto max-w-2xl space-y-7">
        <div className="flex flex-col items-center gap-3">
          <Logo size="lg" />
          <p className="text-[11px] uppercase tracking-label text-muted-soft">
            Welcome aboard · let's get you set up
          </p>
        </div>

        <WizardProgress current={currentStep} />

        <Card>
          <CardContent className="space-y-6 px-7 py-8">
            <h1 className={PAGE_TITLE}>
              {STEP_LABELS[currentStep] ?? currentStep}
            </h1>
            {currentStep === 'account' && <AccountStep />}
            {currentStep === 'agency' && <AgencyStep />}
            {currentStep === 'baa' && <BAAStep />}
            {currentStep === 'launch' && <LaunchStep />}
          </CardContent>
        </Card>

        {/* Symmetric entry point back to sign-in, shown only on the first step
            (once the user is mid-wizard a stray link away would lose progress). */}
        {currentStep === 'account' && (
          <p className="text-center text-[13px] text-muted">
            Already have an account?{' '}
            <Link
              to="/login"
              className="font-bold text-azure no-underline hover:underline"
            >
              Sign in
            </Link>
          </p>
        )}
      </div>
    </div>
  );
}
