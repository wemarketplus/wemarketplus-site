import { LegalShell } from '../components/LegalShell';
import { LegalBlocks } from '../components/LegalBlocks';
import { TOS_BLOCKS, TOS_EFFECTIVE } from '../constants/legalContent';

export function TermsPage() {
  return (
    <LegalShell eyebrow="Legal" title="Terms of Service" effective={TOS_EFFECTIVE}>
      <LegalBlocks blocks={TOS_BLOCKS} />
    </LegalShell>
  );
}
