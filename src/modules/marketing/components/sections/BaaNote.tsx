import { Link } from 'react-router-dom';

// index.html #baa — HIPAA Business Associate Agreement note.
export function BaaNote() {
  return (
    <section id="baa" className="mx-auto max-w-[860px] px-7 py-12">
      <div className="rounded-[16px] border border-white/[0.08] bg-white/[0.03] p-8">
        <h3 className="mb-3 font-serif-display text-[22px] text-foreground">
          Business Associate Agreement (BAA)
        </h3>
        <p className="mb-3 text-[14px] leading-[1.74] text-muted">
          In compliance with HIPAA, We Market Plus LLC provides a standard
          Business Associate Agreement for all subscribing clients. The BAA is
          acknowledged at checkout for every plan tier, and a copy is delivered
          to your email upon subscription confirmation.
        </p>
        <p className="text-[14px] leading-[1.74] text-muted">
          We Market Plus LLC implements appropriate administrative, physical, and
          technical safeguards to protect PHI in accordance with the HIPAA
          Security Rule.{' '}
          <Link to="/contact" className="font-semibold text-azure hover:underline">
            Questions? Contact us
          </Link>
          .
        </p>
      </div>
    </section>
  );
}
