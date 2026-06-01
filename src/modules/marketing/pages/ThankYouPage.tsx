import { Link } from 'react-router-dom';
import { Sparkles } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { MarketingShell } from '../components/MarketingShell';

export function ThankYouPage() {
  return (
    <MarketingShell>
      <section className="mx-auto max-w-2xl px-6 py-24 text-center animate-slide-up">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-primary/15 text-primary ring-1 ring-primary/30">
          <Sparkles className="h-6 w-6" />
        </div>
        <h1 className="mt-4 font-serif-display text-4xl text-foreground">
          Thanks — we'll be in touch.
        </h1>
        <p className="mt-3 text-sm text-muted">
          Your request landed. Someone on our team will reach out within one
          business day.
        </p>
        <div className="mt-8 flex justify-center gap-2">
          <Link to="/">
            <Button variant="secondary">Back to homepage</Button>
          </Link>
          <Link to="/demo/hospicelink/pro">
            <Button>Explore the demo</Button>
          </Link>
        </div>
      </section>
    </MarketingShell>
  );
}
