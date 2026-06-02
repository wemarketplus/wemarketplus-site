// index.html #contact — "Questions? We Are Here." with email + phone CTAs.
export function ContactSection() {
  return (
    <section
      id="contact"
      className="mx-auto max-w-[700px] px-7 py-12 text-center"
    >
      <h2 className="mb-2 font-serif-display text-[26px] text-foreground">
        Questions? We Are Here.
      </h2>
      <p className="mb-6 text-[14px] text-muted">
        Our team responds within a few hours on business days.
      </p>
      <div className="flex flex-wrap justify-center gap-3">
        <a
          href="mailto:info@wemarketplus.com"
          className="rounded-pill bg-sage px-[22px] py-[11px] text-[13px] font-bold text-[#06080e] transition-opacity hover:opacity-[0.88]"
        >
          info@wemarketplus.com
        </a>
        <a
          href="tel:+14697930673"
          className="rounded-pill border border-white/[0.14] px-[22px] py-[11px] text-[13px] font-semibold text-foreground transition-colors hover:border-white/[0.28] hover:bg-white/[0.05]"
        >
          (469) 793-0673
        </a>
      </div>
    </section>
  );
}
