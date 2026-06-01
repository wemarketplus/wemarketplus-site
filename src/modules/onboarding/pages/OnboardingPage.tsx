import { Card, CardContent, Logo } from '@/shared/ui/core';
import { useOnboarding } from '../hooks/useOnboarding';
import { STEP_LABELS } from '../constants/onboardingConstants';
import { WizardProgress } from '../components/WizardProgress';
import { AccountStep } from '../components/AccountStep';
import { AgencyStep } from '../components/AgencyStep';
import { BAAStep } from '../components/BAAStep';
import { LaunchStep } from '../components/LaunchStep';

export function OnboardingPage() {
  const { currentStep } = useOnboarding();

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
          <p className="text-[11px] uppercase tracking-[0.16em] text-muted-soft">
            Welcome aboard · let's get you set up
          </p>
        </div>

        <WizardProgress current={currentStep} />

        <Card>
          <CardContent className="space-y-6 px-7 py-8">
            <h1 className="font-display text-3xl text-foreground">
              {STEP_LABELS[currentStep] ?? currentStep}
            </h1>
            {currentStep === 'account' && <AccountStep />}
            {currentStep === 'agency' && <AgencyStep />}
            {currentStep === 'baa' && <BAAStep />}
            {currentStep === 'launch' && <LaunchStep />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
