import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { setCredentials } from '@/modules/auth';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useOnboardMutation } from '../api/onboardingApi';
import { useOnboarding } from './useOnboarding';
import type { BAAFormValues } from '../schema/onboardingSchema';
import type {
  AccountInfo,
  AgencyInfo,
  OnboardRequest,
} from '../types/onboardingTypes';

// Orchestrates the final onboarding submission: persists the BAA signature,
// guards that earlier steps are complete, posts the onboard payload, stores
// credentials, and advances on success. When email verification is enforced
// the register response carries no tokens — we advance to the launch step in
// its "check your email" state instead of storing credentials. Kept out of
// the component so BAAStep stays presentation-only.
export function useOnboardingSubmit() {
  const { draft, next, saveBAA, markCompleted, markPendingVerification } =
    useOnboarding();
  const dispatch = useAppDispatch();
  const [onboard, state] = useOnboardMutation();

  const submitBAA = async (values: BAAFormValues) => {
    saveBAA(values);
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
      baa: values,
      stripeSessionId: draft.stripeSessionId,
    };
    try {
      const result = await onboard(payload).unwrap();
      if (result.requiresEmailVerification && !result.accessToken) {
        // Production path: account created, tokens withheld until the user
        // clicks the emailed verification link. Don't sign them in.
        markPendingVerification(result.user.email);
        next();
        return;
      }
      dispatch(
        setCredentials({
          token: result.accessToken ?? null,
          refreshToken: result.refreshToken ?? null,
          user: result.user,
        }),
      );
      markCompleted();
      next();
    } catch (err) {
      toast.error(
        extractApiErrorMessage(err, "Couldn't activate your workspace"),
      );
    }
  };

  return { submitBAA, isSubmitting: state.isLoading };
}
