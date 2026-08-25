import { Link } from 'react-router-dom';

// Mirrors wemarketplus-site `.badge-hipaa` + footer link row exactly:
// a 🔒 azure-bordered pill reading "HIPAA-Compliant & SOC 2 Ready", then a
// Privacy · Terms link line.
//
// The links are `text-muted` (#6a726e ≈ 4.9:1 on the white auth page), NOT
// `text-faint` (#a8b0ac ≈ 2.2:1) — faint is the placeholder token and left
// these two legal links effectively invisible. They also carry a permanent
// underline so they read as links rather than as grey caption text.
const legalLink =
  'font-semibold text-muted underline decoration-muted/40 underline-offset-2 ' +
  'hover:text-primary hover:decoration-primary/60';

export function SecurityBadges() {
  return (
    <div className="text-center">
      <div className="inline-flex items-center gap-1.5 rounded-pill border border-primary/20 bg-primary/[0.06] px-3 py-1 text-[11px] text-primary">
        🔒 HIPAA-Compliant &amp; SOC 2 Ready
      </div>
      <div className="mt-3 text-[12px] text-muted">
        <Link to="/privacy" className={legalLink}>
          Privacy Policy
        </Link>
        <span className="px-2 text-muted/60">·</span>
        <Link to="/terms" className={legalLink}>
          Terms of Service
        </Link>
      </div>
    </div>
  );
}
