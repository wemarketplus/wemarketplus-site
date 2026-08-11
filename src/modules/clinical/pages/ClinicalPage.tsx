import { useLocation } from 'react-router-dom';
import { AdmissionsPage } from './AdmissionsPage';
import { FamilyCommunicationPage } from './FamilyCommunicationPage';
import { TelehealthPage } from './TelehealthPage';

// The three /clinical/* routes all mount this component (see app/router.tsx), so
// the active sub-view is derived from the pathname:
//   /clinical/admissions -> bed-units CRUD
//   /clinical/family     -> the family communication LOG (phone/text/in-person)
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

  /**
   * Default (/clinical/family) — the family communication log.
   *
   * This used to render TelehealthPage ("Family telehealth visits"). Video visits
   * are a different product surface from the log of phone/text/in-person family
   * conversations the nurse guide sends people here to keep, and only the log is
   * built: Telehealth & patient portal is announced as coming soon in the sidebar.
   */
  return <FamilyCommunicationPage />;
}
