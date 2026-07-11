import { useLocation } from 'react-router-dom';
import { AdmissionsPage } from './AdmissionsPage';
import { TelehealthPage } from './TelehealthPage';

// The three /clinical/* routes all mount this component (see app/router.tsx), so
// the active sub-view is derived from the pathname:
//   /clinical/admissions -> bed-units CRUD
//   /clinical/family     -> telehealth sessions (family visits framing)
//   /clinical/messaging  -> telehealth sessions (care-team framing)
// Each is a real list + create/edit/delete against the clinicalApi.
export function ClinicalPage() {
  const { pathname } = useLocation();

  if (pathname.includes('/clinical/admissions')) {
    return <AdmissionsPage />;
  }

  if (pathname.includes('/clinical/messaging')) {
    return (
      <TelehealthPage
        title="Care-team telehealth"
        subtitle={(total) => `${total} video visits coordinated with the care team`}
      />
    );
  }

  // Default (/clinical/family) — family-facing video visits.
  return (
    <TelehealthPage
      title="Family telehealth visits"
      subtitle={(total) => `${total} scheduled video visits with families`}
    />
  );
}
