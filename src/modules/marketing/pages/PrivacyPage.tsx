import { LegalShell } from '../components/LegalShell';
import { LegalBlocks } from '../components/LegalBlocks';
import { PRIVACY_BLOCKS, PRIVACY_EFFECTIVE } from '../constants/legalContent';

export function PrivacyPage() {
  return (
    <LegalShell eyebrow="Legal" title="Privacy Policy" effective={PRIVACY_EFFECTIVE}>
      <LegalBlocks blocks={PRIVACY_BLOCKS} />
    </LegalShell>
  );
}
