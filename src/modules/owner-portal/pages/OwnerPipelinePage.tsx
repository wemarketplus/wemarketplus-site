import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OwnerPipelineBoard } from '../components/OwnerPipelineBoard';
import { OWNER_PIPELINE } from '../constants/ownerFixtures';

export function OwnerPipelinePage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Sales pipeline"
        description="Every deal in motion grouped by stage."
      />

      <OwnerPipelineBoard deals={OWNER_PIPELINE} />
    </div>
  );
}
