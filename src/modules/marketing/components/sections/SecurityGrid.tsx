import { ShieldCheck } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeading } from '../SectionHeading';
import { SECURITY_CARDS } from '../../constants/landingContent';

// index.html #security — "HIPAA-Ready from Day One", plain 64px/1000px
// centred section (no tinted band on the live site).
export function SecurityGrid() {
  return (
    <section
      id="security"
      className="mx-auto max-w-[1000px] px-7 py-16 text-center"
    >
      <SectionHeading
        kicker="Enterprise Security"
        tone="sage"
        title="HIPAA-Ready from Day One"
        body="TLS 1.3 in transit. AES-256 at rest. BAA executed at checkout for every plan. Gold adds full HIPAA Audit Logging."
      />
      <div className="grid grid-cols-1 gap-4 text-left sm:grid-cols-2 lg:grid-cols-3">
        {SECURITY_CARDS.map((c) => (
          <Card key={c.title}>
            <CardContent className="space-y-3 p-6">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-sage/15 text-sage ring-1 ring-sage/20">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <h3 className="text-[15px] font-bold text-foreground">{c.title}</h3>
              <p className="text-[13px] leading-[1.66] text-muted">{c.body}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
