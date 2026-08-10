import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { CheckCircle2 } from 'lucide-react';
import { Button, Card, CardContent, Input, Label, Logo, Textarea } from '@/shared/ui/core';
import {
  useResolvePortalQuery,
  useSubmitPortalReferralMutation,
} from '../api/referralPortalApi';

/**
 * The page a facility reaches from its QR code or link.
 *
 * PUBLIC and unauthenticated. It shows only who the referral is going to, takes
 * a patient name and two optional fields, and confirms receipt. It never renders
 * a record back, because the API never returns one — this is the browser half of
 * the write-only guarantee that makes the endpoint safe to expose.
 *
 * A dead link (unknown, revoked or expired) gets one indistinguishable message,
 * matching the server, so the page cannot be used to probe which tokens exist.
 */
export function PublicReferralFormPage() {
  const { token = '' } = useParams<{ token: string }>();
  const { data: context, isLoading, isError } = useResolvePortalQuery(token, {
    skip: !token,
  });
  const [submit, { isLoading: isSubmitting }] = useSubmitPortalReferralMutation();

  const [values, setValues] = useState({
    patientName: '',
    referringPerson: '',
    diagnosisReason: '',
  });
  const [receipt, setReceipt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const set = (key: keyof typeof values, value: string) =>
    setValues((v) => ({ ...v, [key]: value }));

  const onSubmit = async () => {
    if (!values.patientName.trim()) {
      setError("Please enter the patient's name.");
      return;
    }
    setError(null);
    try {
      const result = await submit({
        token,
        body: {
          patientName: values.patientName.trim(),
          referringPerson: values.referringPerson.trim() || undefined,
          diagnosisReason: values.diagnosisReason.trim() || undefined,
        },
      }).unwrap();
      setReceipt(result.message);
    } catch {
      setError('We could not send this referral. Please try again, or call us.');
    }
  };

  return (
    <div className="mx-auto flex min-h-screen max-w-lg flex-col justify-center px-4 py-10">
      <div className="mb-6 flex justify-center">
        <Logo />
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading…
          </CardContent>
        </Card>
      ) : isError || !context ? (
        <Card>
          <CardContent className="space-y-2 px-6 py-8">
            <h1 className="text-lg font-semibold text-foreground">
              This referral link is no longer available
            </h1>
            <p className="text-sm text-muted">
              Please contact your hospice liaison for a current link.
            </p>
          </CardContent>
        </Card>
      ) : receipt ? (
        <Card>
          <CardContent className="space-y-3 px-6 py-8 text-center">
            <CheckCircle2 className="mx-auto h-10 w-10 text-success" />
            <h1 className="text-lg font-semibold text-foreground">
              Referral received
            </h1>
            <p className="text-sm text-muted">{receipt}</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="space-y-5 px-6 py-7">
            <header className="space-y-1">
              <h1 className="font-display text-2xl text-foreground">
                Refer a patient
              </h1>
              <p className="text-sm text-muted">
                From <strong>{context.facilityName}</strong> to{' '}
                <strong>{context.organizationName}</strong>
              </p>
            </header>

            <div>
              <Label htmlFor="pr-name">Patient name</Label>
              <Input
                id="pr-name"
                value={values.patientName}
                onChange={(e) => set('patientName', e.target.value)}
                autoComplete="off"
              />
            </div>

            <div>
              <Label htmlFor="pr-person">Referring clinician (optional)</Label>
              <Input
                id="pr-person"
                value={values.referringPerson}
                onChange={(e) => set('referringPerson', e.target.value)}
                autoComplete="off"
              />
            </div>

            <div>
              <Label htmlFor="pr-reason">Reason for referral (optional)</Label>
              <Textarea
                id="pr-reason"
                value={values.diagnosisReason}
                onChange={(e) => set('diagnosisReason', e.target.value)}
              />
            </div>

            {error && <p className="text-[12px] text-destructive">{error}</p>}

            <Button onClick={onSubmit} disabled={isSubmitting} className="w-full">
              {isSubmitting ? 'Sending…' : 'Send referral'}
            </Button>

            {/* Says plainly what happens next and what NOT to put in the form.
                A public intake box that invites clinical detail would collect
                more PHI than the flow needs on an unauthenticated surface. */}
            <p className="text-[11px] text-muted-soft">
              The intake team will contact you to collect clinical details.
              Please do not include medical records or identifiers here.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
