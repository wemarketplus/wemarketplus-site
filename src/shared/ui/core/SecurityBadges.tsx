import { Link } from 'react-router-dom';

// Mirrors wemarketplus-site `.badge-hipaa` + footer link row exactly:
// a 🔒 azure-bordered pill reading "HIPAA-Compliant & SOC 2 Ready", then a
// Privacy · Terms link line in faint text.
export function SecurityBadges() {
  return (
    <div className="text-center">
      <div className="inline-flex items-center gap-1.5 rounded-pill border border-primary/20 bg-primary/[0.06] px-3 py-1 text-[11px] text-primary">
        🔒 HIPAA-Compliant &amp; SOC 2 Ready
      </div>
      <div className="mt-3 text-[11px] text-faint">
        <Link to="/privacy" className="text-faint no-underline hover:text-muted">
          Privacy Policy
        </Link>
        <span className="px-2">·</span>
        <Link to="/terms" className="text-faint no-underline hover:text-muted">
          Terms of Service
        </Link>
      </div>
    </div>
  );
}
