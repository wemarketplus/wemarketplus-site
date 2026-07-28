import { useState } from 'react';
import { Smartphone } from 'lucide-react';
import { Button, Card, CardContent, Input, Label, PasswordInput } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { useMeQuery, useMfaManagement } from '@/modules/auth';

// Security tab "Two-factor authentication" section. Reads the current status
// from /auth/me and drives the enable (setup -> scan QR -> confirm code) and
// disable (code OR password) flows via useMfaManagement.
export function TwoFactorCard() {
  const { data: me } = useMeQuery();
  const enabled = Boolean(me?.mfaEnabled);
  const {
    startSetup,
    confirmEnable,
    disableMfa,
    pendingSetup,
    clearSetup,
    isStartingSetup,
    isEnabling,
    isDisabling,
  } = useMfaManagement();

  const [enableOpen, setEnableOpen] = useState(false);
  const [disableOpen, setDisableOpen] = useState(false);
  const [code, setCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');

  const onlyDigits = (v: string) => v.replace(/\D/g, '').slice(0, 6);

  const openEnable = async () => {
    setCode('');
    const ok = await startSetup();
    if (ok) setEnableOpen(true);
  };

  const closeEnable = () => {
    setEnableOpen(false);
    setCode('');
    clearSetup();
  };

  const submitEnable = async () => {
    const ok = await confirmEnable(code);
    if (ok) closeEnable();
  };

  const openDisable = () => {
    setDisableCode('');
    setDisablePassword('');
    setDisableOpen(true);
  };

  const submitDisable = async () => {
    const ok = await disableMfa({
      code: disableCode || undefined,
      password: disablePassword || undefined,
    });
    if (ok) setDisableOpen(false);
  };

  return (
    <>
      <Card>
        <CardContent className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
              <Smartphone className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-semibold text-foreground">
                  Two-factor authentication
                </h2>
                <span
                  className={
                    enabled
                      ? 'rounded-pill border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 text-[10px] uppercase tracking-[0.08em] text-emerald-300'
                      : 'rounded-pill border border-border/[0.08] bg-foreground/[0.03] px-2.5 py-1 text-[10px] uppercase tracking-[0.08em] text-muted-soft'
                  }
                >
                  {enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <p className="mt-1 text-sm text-muted">
                Add a second factor to every sign-in with an authenticator app (TOTP).
              </p>
            </div>
          </div>
          {enabled ? (
            <Button variant="secondary" onClick={openDisable}>
              Disable
            </Button>
          ) : (
            <Button variant="secondary" onClick={openEnable} disabled={isStartingSetup}>
              {isStartingSetup ? 'Preparing…' : 'Enable'}
            </Button>
          )}
        </CardContent>
      </Card>

      <Modal
        open={enableOpen}
        onClose={closeEnable}
        title="Enable two-factor authentication"
        size="sm"
        footer={
          <>
            <Button variant="secondary" onClick={closeEnable}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={submitEnable}
              disabled={isEnabling || code.length !== 6}
            >
              {isEnabling ? 'Verifying…' : 'Verify & enable'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-muted">
            Scan this QR code with your authenticator app (Google Authenticator, 1Password,
            Authy…), then enter the 6-digit code it shows.
          </p>
          {pendingSetup && (
            <div className="flex flex-col items-center gap-3">
              <img
                src={pendingSetup.qrDataUrl}
                alt="Two-factor QR code"
                className="h-44 w-44 rounded-md bg-white p-2"
              />
              <div className="w-full">
                <Label htmlFor="mfa-secret">Or enter this key manually</Label>
                <Input
                  id="mfa-secret"
                  readOnly
                  value={pendingSetup.secret}
                  className="mt-1 font-mono text-xs"
                  onFocus={(e) => e.currentTarget.select()}
                />
              </div>
            </div>
          )}
          <div>
            <Label htmlFor="mfa-enable-code">Authentication code</Label>
            <Input
              id="mfa-enable-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(onlyDigits(e.target.value))}
              className="mt-1"
            />
          </div>
        </div>
      </Modal>

      <Modal
        open={disableOpen}
        onClose={() => setDisableOpen(false)}
        title="Disable two-factor authentication"
        size="sm"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDisableOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={submitDisable}
              disabled={isDisabling || (disableCode.length !== 6 && disablePassword.length === 0)}
            >
              {isDisabling ? 'Disabling…' : 'Disable'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-muted">
            Confirm it's you with a current authenticator code or your account password.
          </p>
          <div>
            <Label htmlFor="mfa-disable-code">Authentication code</Label>
            <Input
              id="mfa-disable-code"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              value={disableCode}
              onChange={(e) => setDisableCode(onlyDigits(e.target.value))}
              className="mt-1"
            />
          </div>
          <div className="text-center text-xs uppercase tracking-[0.08em] text-muted-soft">
            or
          </div>
          <div>
            <Label htmlFor="mfa-disable-password">Account password</Label>
            <PasswordInput
              id="mfa-disable-password"
              autoComplete="current-password"
              placeholder="••••••••"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
              className="mt-1"
            />
          </div>
        </div>
      </Modal>
    </>
  );
}
