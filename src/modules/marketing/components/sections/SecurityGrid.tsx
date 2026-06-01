import { ShieldCheck } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { SECURITY_CARDS } from '../../constants/landingContent';

// index.html #security — "HIPAA-Ready from Day One", 6 cards.
export function SecurityGrid() {
  return (
    <section id="security" className="border-y border-white/[0.06] bg-white/[0.015]">
      <div className="mx-auto max-w-7xl px-6 py-20">
        <div className="mb-10 text-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
            Enterprise Security
          </p>
          <h2 className="mt-3 font-serif-display text-3xl font-black text-foreground sm:text-4xl">
            HIPAA-Ready from Day One
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-muted">
            TLS 1.3 in transit. AES-256 at rest. BAA executed at checkout for every
            plan. Gold adds full HIPAA Audit Logging.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {SECURITY_CARDS.map((c) => (
            <Card key={c.title}>
              <CardContent className="space-y-3 px-5 py-6">
                <div className="flex h-10 w-10 items-center justify-center rounded-md bg-sage/15 text-sage ring-1 ring-sage/20">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <h3 className="text-base font-bold text-foreground">{c.title}</h3>
                <p className="text-sm leading-relaxed text-muted">{c.body}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
