import { Button } from '@/shared/ui/core';

// index.html #contact — "Questions? We Are Here." with email + phone CTAs.
export function ContactSection() {
  return (
    <section id="contact" className="mx-auto max-w-2xl px-6 py-20 text-center">
      <h2 className="font-serif-display text-4xl text-foreground">
        Questions? We Are Here.
      </h2>
      <p className="mt-3 text-sm text-muted">
        Our team responds within a few hours on business days.
      </p>
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        <a href="mailto:info@wemarketplus.com">
          <Button className="bg-sage text-[#06080e]">info@wemarketplus.com</Button>
        </a>
        <a href="tel:+14697930673">
          <Button variant="outline">(469) 793-0673</Button>
        </a>
      </div>
    </section>
  );
}
