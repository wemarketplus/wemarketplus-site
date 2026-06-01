import { KeyRound, Smartphone, History } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button, Card, CardContent } from '@/shared/ui/core';

export function SecurityTab() {
  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
              <KeyRound className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-foreground">Password</h2>
              <p className="mt-1 text-sm text-muted">
                Rotate your password — recommended every 90 days.
              </p>
            </div>
          </div>
          <Link to="/account/password">
            <Button variant="secondary">Change password</Button>
          </Link>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-white/[0.06] text-muted ring-1 ring-white/[0.08]">
              <Smartphone className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-foreground">
                Two-factor authentication
              </h2>
              <p className="mt-1 text-sm text-muted">
                Add a second factor to every sign-in (TOTP).
              </p>
            </div>
          </div>
          <span className="rounded-pill border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[10px] uppercase tracking-[0.08em] text-muted-soft">
            Backend pending
          </span>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-white/[0.06] text-muted ring-1 ring-white/[0.08]">
              <History className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-foreground">
                Recent sign-ins
              </h2>
              <p className="mt-1 text-sm text-muted">
                See devices and locations on your account.
              </p>
            </div>
          </div>
          <span className="rounded-pill border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[10px] uppercase tracking-[0.08em] text-muted-soft">
            Backend pending
          </span>
        </CardContent>
      </Card>
    </div>
  );
}
